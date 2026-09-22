export type ElfHeader={bits:32|64;littleEndian:boolean,type:number,machine:number};export function parseHeader(data:Uint8Array):ElfHeader{if(data.length<20||data[0]!==127||data[1]!==69||data[2]!==76||data[3]!==70)throw new Error('not elf');const bits=data[4]===1?32:data[4]===2?64:0;if(!bits)throw new Error('class');const little=data[5]===1;const read=(at:number)=>little?data[at]|data[at+1]<<8:data[at]<<8|data[at+1];return{bits:bits as 32|64,littleEndian:little,type:read(16),machine:read(18)}}

// How to decode string bytes that are not valid UTF-8.
// 'replace': U+FFFD per invalid sequence (TextDecoder, fatal:false). 'bytes': one char per byte.
export type Utf8Policy='replace'|'bytes';

// A string table bounded to its section: indexes must be < the declared section
// size, and a string is only valid if its NUL terminator lies inside the view.
// The view is clamped to the file so a truncated section never reads past EOF.
export type StringTable={
  readonly size:number;
  readonly view:Uint8Array;
  get(index:number):string|null;
  getBytes(index:number):Uint8Array|null;
};

const utf8=new TextDecoder('utf-8',{fatal:false});

export function createStringTable(data:Uint8Array,offset:number,size:number,policy:Utf8Policy='replace'):StringTable{
  const start=Math.min(Math.max(offset,0),data.length);
  const view=data.subarray(start,Math.min(start+Math.max(size,0),data.length));
  const span=(index:number):[number,number]|null=>{
    if(!Number.isInteger(index)||index<0||index>=size||index>=view.length)return null;
    let end=index;
    while(end<view.length&&view[end]!==0)end++;
    return end<view.length?[index,end]:null;
  };
  const decode=(b:Uint8Array):string=>policy==='bytes'?String.fromCharCode(...b):utf8.decode(b);
  return{
    size,
    view,
    getBytes(index){const s=span(index);return s?view.subarray(s[0],s[1]):null},
    // Index 0 is the empty name by ELF convention, as long as the table is non-empty.
    get(index){if(index===0&&size>0)return'';const s=span(index);return s?decode(view.subarray(s[0],s[1])):null},
  };
}

export type SectionHeader={nameOffset:number;type:number;flags:number;addr:number;offset:number;size:number;link:number;info:number;addrAlign:number;entSize:number};

function readers(data:Uint8Array,little:boolean){
  const u16=(at:number)=>little?data[at]|data[at+1]<<8:data[at]<<8|data[at+1];
  const u32=(at:number)=>little?(data[at]|data[at+1]<<8|data[at+2]<<16|data[at+3]<<24)>>>0:(data[at]<<24|data[at+1]<<16|data[at+2]<<8|data[at+3])>>>0;
  const u64=(at:number)=>little?u32(at)+u32(at+4)*2**32:u32(at)*2**32+u32(at+4);
  return{u16,u32,u64};
}

// Parses the section header table. Headers cut off by EOF are dropped, and the
// extended numbering scheme is honored (e_shnum==0 -> sh_size of section 0).
export function parseSectionHeaders(data:Uint8Array):SectionHeader[]{
  const h=parseHeader(data);
  const is64=h.bits===64;
  const{u16,u32,u64}=readers(data,h.littleEndian);
  const shoff=is64?u64(0x28):u32(0x20);
  if(!shoff)return[];
  const ent=u16(is64?0x3a:0x2e);
  const min=is64?64:40;
  if(ent<min)return[];
  const read=(i:number):SectionHeader|null=>{
    const o=shoff+i*ent;
    if(o+min>data.length)return null;
    return is64
      ?{nameOffset:u32(o),type:u32(o+4),flags:u64(o+8),addr:u64(o+16),offset:u64(o+24),size:u64(o+32),link:u32(o+40),info:u32(o+44),addrAlign:u64(o+48),entSize:u64(o+56)}
      :{nameOffset:u32(o),type:u32(o+4),flags:u32(o+8),addr:u32(o+12),offset:u32(o+16),size:u32(o+20),link:u32(o+24),info:u32(o+28),addrAlign:u32(o+32),entSize:u32(o+36)};
  };
  const first=read(0);
  let num=u16(is64?0x3c:0x30);
  if(num===0)num=first?first.size:0;
  const out:SectionHeader[]=[];
  for(let i=0;i<num;i++){const s=read(i);if(!s)break;out.push(s);}
  return out;
}

// Section names resolve against the e_shstrndx string table only; a bad
// sh_name offset yields null for that section, never a neighboring string.
export function sectionNames(data:Uint8Array,policy:Utf8Policy='replace'):(string|null)[]{
  const h=parseHeader(data);
  const is64=h.bits===64;
  const{u16}=readers(data,h.littleEndian);
  const secs=parseSectionHeaders(data);
  let ndx=u16(is64?0x3e:0x32);
  if(ndx===0xffff)ndx=secs.length?secs[0].link:0;
  if(ndx===0||ndx>=secs.length)return secs.map(()=>null);
  const t=createStringTable(data,secs[ndx].offset,secs[ndx].size,policy);
  return secs.map(s=>t.get(s.nameOffset));
}

export type ElfSymbol={sectionIndex:number;symbolIndex:number;nameOffset:number;name:string|null;info:number;other:number;shndx:number;value:number;size:number};

// Symbol names resolve against the string table named by the symbol section's
// sh_link. Symbols whose name fails to resolve keep name===null.
export function parseSymbols(data:Uint8Array,policy:Utf8Policy='replace'):ElfSymbol[]{
  const h=parseHeader(data);
  const is64=h.bits===64;
  const{u16,u32,u64}=readers(data,h.littleEndian);
  const secs=parseSectionHeaders(data);
  const min=is64?24:16;
  const out:ElfSymbol[]=[];
  secs.forEach((sec,si)=>{
    if(sec.type!==2&&sec.type!==11)return; // SHT_SYMTAB / SHT_DYNSYM
    const table=sec.link<secs.length?createStringTable(data,secs[sec.link].offset,secs[sec.link].size,policy):null;
    const ent=sec.entSize>=min?sec.entSize:min;
    const count=Math.floor(sec.size/ent);
    for(let i=0;i<count;i++){
      const o=sec.offset+i*ent;
      if(o+min>data.length)break;
      const nameOffset=u32(o);
      const fields=is64
        ?{info:data[o+4],other:data[o+5],shndx:u16(o+6),value:u64(o+8),size:u64(o+16)}
        :{info:data[o+12],other:data[o+13],shndx:u16(o+14),value:u32(o+4),size:u32(o+8)};
      out.push({sectionIndex:si,symbolIndex:i,nameOffset,...fields,name:table?table.get(nameOffset):null});
    }
  });
  return out;
}

// Name -> symbols lookup. Symbols whose name failed to resolve (null) are
// never entered into the index.
export function symbolIndex(symbols:ElfSymbol[]):Map<string,ElfSymbol[]>{
  const m=new Map<string,ElfSymbol[]>();
  for(const s of symbols){
    if(s.name===null)continue;
    const a=m.get(s.name);
    if(a)a.push(s);else m.set(s.name,[s]);
  }
  return m;
}
