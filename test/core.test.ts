import{expect,it,describe}from'vitest';import{parseHeader,createStringTable,parseSectionHeaders,sectionNames,parseSymbols,symbolIndex}from'../src/index.js';it('parses',()=>{const x=new Uint8Array(20);x.set([127,69,76,70,1,1]);expect(parseHeader(x).bits).toBe(32)});

const enc=new TextEncoder();
const ascii=(s:string)=>enc.encode(s);
const cat=(...parts:Uint8Array[])=>{const n=parts.reduce((a,p)=>a+p.length,0);const o=new Uint8Array(n);let at=0;for(const p of parts){o.set(p,at);at+=p.length;}return o;};

type Sec={name:string;type:number;link?:number;info?:number;entsize?:number;body:Uint8Array;declaredSize?:number};

// Builds a minimal little-endian ELF with a null section, the given sections,
// and a trailing .shstrtab. Bodies come first, section headers last.
function buildElf(bits:32|64,sections:Sec[],opts:{shstrndx?:number}={}):Uint8Array{
  const is64=bits===64;
  let shstr=ascii('\0');
  const nameOff:number[]=[0];
  for(const s of sections){nameOff.push(shstr.length);shstr=cat(shstr,ascii(s.name+'\0'));}
  nameOff.push(shstr.length);shstr=cat(shstr,ascii('.shstrtab\0'));
  const all:Sec[]=[{name:'',type:0,body:new Uint8Array(0)},...sections,{name:'.shstrtab',type:3,body:shstr}];
  const ehsize=is64?64:52,shentsize=is64?64:40;
  let off=ehsize;
  const offs=all.map(s=>{const o=off;off+=s.body.length;return o;});
  const shoff=off;
  const buf=new Uint8Array(shoff+all.length*shentsize);
  const dv=new DataView(buf.buffer);
  buf.set([0x7f,0x45,0x4c,0x46,is64?2:1,1,1]);
  dv.setUint16(16,1,true);dv.setUint16(18,is64?62:40,true);dv.setUint32(20,1,true);
  if(is64)dv.setBigUint64(40,BigInt(shoff),true);else dv.setUint32(0x20,shoff,true);
  dv.setUint16(is64?52:40,ehsize,true);
  dv.setUint16(is64?58:46,shentsize,true);
  dv.setUint16(is64?60:48,all.length,true);
  dv.setUint16(is64?62:50,opts.shstrndx??all.length-1,true);
  all.forEach((s,i)=>{
    buf.set(s.body,offs[i]);
    const o=shoff+i*shentsize;
    const size=s.declaredSize??s.body.length;
    dv.setUint32(o,nameOff[i],true);
    dv.setUint32(o+4,s.type,true);
    if(is64){
      dv.setBigUint64(o+24,BigInt(offs[i]),true);
      dv.setBigUint64(o+32,BigInt(size),true);
      dv.setUint32(o+40,s.link??0,true);
      dv.setUint32(o+44,s.info??0,true);
      dv.setBigUint64(o+56,BigInt(s.entsize??0),true);
    }else{
      dv.setUint32(o+16,offs[i],true);
      dv.setUint32(o+20,size,true);
      dv.setUint32(o+24,s.link??0,true);
      dv.setUint32(o+28,s.info??0,true);
      dv.setUint32(o+36,s.entsize??0,true);
    }
  });
  return buf;
}

function sym64(name:number,info=0x12,shndx=1,value=0,size=0):Uint8Array{
  const b=new Uint8Array(24);const dv=new DataView(b.buffer);
  dv.setUint32(0,name,true);b[4]=info;b[5]=0;dv.setUint16(6,shndx,true);
  dv.setBigUint64(8,BigInt(value),true);dv.setBigUint64(16,BigInt(size),true);
  return b;
}

describe('createStringTable',()=>{
  it('index 0 returns the empty string',()=>{
    const t=createStringTable(ascii('\0foo\0'),0,5);
    expect(t.get(0)).toBe('');
    expect(t.get(1)).toBe('foo');
  });
  it('empty table rejects even index 0',()=>{
    expect(createStringTable(new Uint8Array(0),0,0).get(0)).toBeNull();
  });
  it('accepts a string terminated by the last byte of the section',()=>{
    const t=createStringTable(ascii('\0ab\0'),0,4);
    expect(t.get(1)).toBe('ab');
  });
  it('rejects a string with no terminator inside the view',()=>{
    const t=createStringTable(ascii('\0abc'),0,4);
    expect(t.get(1)).toBeNull();
    expect(t.getBytes(1)).toBeNull();
  });
  it('never reads past the view into the next section bytes',()=>{
    // Regression: table ends with "\0fo" (no NUL); "obar\0" follows in the file.
    const data=cat(ascii('\0fo'),ascii('obar\0'));
    const t=createStringTable(data,0,3);
    expect(t.get(1)).toBeNull();
  });
  it('rejects out-of-bounds indexes',()=>{
    const t=createStringTable(ascii('\0a\0'),0,3);
    expect(t.get(3)).toBeNull();   // index == size
    expect(t.get(99)).toBeNull();
    expect(t.get(-1)).toBeNull();
    expect(t.get(1.5)).toBeNull();
    expect(t.getBytes(3)).toBeNull();
  });
  it('decodes invalid UTF-8 with replacement by default',()=>{
    const t=createStringTable(new Uint8Array([0,0xff,0xfe,0]),0,4);
    expect(t.get(1)).toBe('��');
    expect(t.getBytes(1)).toEqual(new Uint8Array([0xff,0xfe]));
  });
  it('decodes invalid UTF-8 byte-wise with the bytes policy',()=>{
    const t=createStringTable(new Uint8Array([0,0xff,0xfe,0]),0,4,'bytes');
    expect(t.get(1)).toBe('ÿþ');
  });
  it('decodes valid multi-byte UTF-8',()=>{
    const t=createStringTable(ascii('\0héllo\0'),0,8);
    expect(t.get(1)).toBe('héllo');
  });
  it('clamps the view when the section is truncated by EOF',()=>{
    const t=createStringTable(ascii('\0he'),0,10);
    expect(t.view.length).toBe(3);
    expect(t.get(1)).toBeNull();   // no terminator before EOF
    expect(t.get(5)).toBeNull();   // inside declared size but past EOF
  });
  it('handles a section offset beyond EOF',()=>{
    const t=createStringTable(ascii('ab'),100,10);
    expect(t.view.length).toBe(0);
    expect(t.get(1)).toBeNull();
  });
});

describe('section names',()=>{
  it('resolves names through the shstrndx table',()=>{
    const elf=buildElf(64,[{name:'.text',type:1,body:ascii('code')},{name:'.data',type:1,body:ascii('d')}]);
    expect(sectionNames(elf)).toEqual(['','.text','.data','.shstrtab']);
  });
  it('returns null names when shstrndx is 0',()=>{
    const elf=buildElf(64,[{name:'.text',type:1,body:ascii('x')}],{shstrndx:0});
    expect(sectionNames(elf)).toEqual([null,null,null]);
  });
  it('parses 32-bit section headers too',()=>{
    const elf=buildElf(32,[{name:'.text',type:1,body:ascii('x')}]);
    expect(sectionNames(elf)).toEqual(['','.text','.shstrtab']);
  });
  it('drops section headers truncated by EOF',()=>{
    const elf=buildElf(64,[{name:'.text',type:1,body:ascii('x')}]);
    const dv=new DataView(elf.buffer);
    const shoff=Number(dv.getBigUint64(40,true));
    const cut=elf.slice(0,shoff+64+10); // second header incomplete
    const secs=parseSectionHeaders(cut);
    expect(secs).toHaveLength(1);
    expect(secs[0].type).toBe(0);
  });
});

describe('symbol names',()=>{
  it('uses the sh_link string table, not the section-name table',()=>{
    // st_name 1 is 'dyn' in .dynstr but '.dynstr' in .shstrtab.
    const elf=buildElf(64,[
      {name:'.dynstr',type:3,body:ascii('\0dyn\0')},
      {name:'.dynsym',type:11,link:1,entsize:24,body:sym64(1)},
    ]);
    const syms=parseSymbols(elf);
    expect(syms).toHaveLength(1);
    expect(syms[0].name).toBe('dyn');
  });
  it('keeps failed names out of the symbol index',()=>{
    const strtab=ascii('\0main\0open'); // 'open' at 6 has no terminator
    const symtab=cat(sym64(0),sym64(1),sym64(6),sym64(50));
    const elf=buildElf(64,[
      {name:'.strtab',type:3,body:strtab},
      {name:'.symtab',type:2,link:1,entsize:24,body:symtab},
    ]);
    const syms=parseSymbols(elf);
    expect(syms.map(s=>s.name)).toEqual(['','main',null,null]);
    const idx=symbolIndex(syms);
    expect([...idx.keys()].sort()).toEqual(['','main']);
    expect(idx.get('main')![0].symbolIndex).toBe(1);
    expect(idx.has(null as unknown as string)).toBe(false);
  });
  it('parses 32-bit symbols',()=>{
    const sym=new Uint8Array(16);
    const sd=new DataView(sym.buffer);
    sd.setUint32(0,1,true);sd.setUint32(4,0x4000,true);sd.setUint32(8,7,true);
    sym[12]=0x12;sd.setUint16(14,1,true);
    const elf=buildElf(32,[
      {name:'.strtab',type:3,body:ascii('\0foo\0')},
      {name:'.symtab',type:2,link:1,entsize:16,body:sym},
    ]);
    const syms=parseSymbols(elf);
    expect(syms).toHaveLength(1);
    expect(syms[0].name).toBe('foo');
    expect(syms[0].value).toBe(0x4000);
    expect(syms[0].size).toBe(7);
  });
  it('resolves nothing past EOF in a truncated string section',()=>{
    // Layout: header(64) | 3 section headers | symtab(2 syms) | strtab.
    // The strtab declares size 16 but the file ends after 6 bytes ("\0main\0").
    const buf=new Uint8Array(310);
    const dv=new DataView(buf.buffer);
    buf.set([0x7f,0x45,0x4c,0x46,2,1,1]);
    dv.setUint16(16,1,true);dv.setUint16(18,62,true);dv.setUint32(20,1,true);
    dv.setBigUint64(40,64n,true);
    dv.setUint16(52,64,true);dv.setUint16(58,64,true);
    dv.setUint16(60,3,true);dv.setUint16(62,0,true);
    const sh=(i:number)=>64+i*64;
    dv.setUint32(sh(1)+4,2,true);                       // SHT_SYMTAB
    dv.setBigUint64(sh(1)+24,256n,true);
    dv.setBigUint64(sh(1)+32,48n,true);
    dv.setUint32(sh(1)+40,2,true);                      // sh_link -> strtab
    dv.setBigUint64(sh(1)+56,24n,true);
    dv.setUint32(sh(2)+4,3,true);                       // SHT_STRTAB
    dv.setBigUint64(sh(2)+24,304n,true);
    dv.setBigUint64(sh(2)+32,16n,true);                 // declared 16, only 6 present
    buf.set(sym64(1),256);                              // -> 'main'
    buf.set(sym64(8),280);                              // < 16 but past EOF
    buf.set(ascii('\0main\0'),304);
    const syms=parseSymbols(buf);
    expect(syms.map(s=>s.name)).toEqual(['main',null]);
    const idx=symbolIndex(syms);
    expect(idx.size).toBe(1);
    expect(idx.has('main')).toBe(true);
  });
});
