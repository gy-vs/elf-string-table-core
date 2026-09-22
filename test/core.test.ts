import { expect, it } from 'vitest';
import { ElfStringTable, parseElf, parseHeader } from '../src/index.js';

const encoder = new TextEncoder();

function cstr(value: string): Uint8Array {
  const bytes = encoder.encode(value);
  const result = new Uint8Array(bytes.length + 1);
  result.set(bytes);
  return result;
}

function concat(parts: Uint8Array[]): Uint8Array {
  const result = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}

interface SectionSpec {
  type?: number;
  name?: string;
  nameBytes?: Uint8Array;
  nameOffset?: number;
  data?: Uint8Array;
  link?: number;
  info?: number;
  entrySize?: number;
  sizeOverride?: number;
  offsetOverride?: number;
}

interface ElfImage {
  bytes: Uint8Array;
  sectionHeaderOffset: number;
  nameOffset: number[];
  dataOffset: number[];
}

function makeElf(sections: SectionSpec[], options: {
  bits?: 32 | 64;
  littleEndian?: boolean;
  shstrIndex?: number | null;
  shstrBytes?: Uint8Array;
  truncate?: number;
} = {}): ElfImage {
  const bits = options.bits ?? 32;
  const littleEndian = options.littleEndian ?? true;
  const ehsize = bits === 32 ? 52 : 64;
  const shentsize = bits === 32 ? 40 : 64;
  const count = sections.length + 1;
  const sectionHeaderOffset = ehsize;
  let dataOffset = sectionHeaderOffset + count * shentsize;
  while (dataOffset % 8 !== 0) dataOffset += 1;

  let builtShstr = new Uint8Array([0]);
  const nameOffset = new Array<number>(sections.length + 1).fill(-1);

  function appendName(bytes: Uint8Array): number {
    const offset = builtShstr.length;
    const next = new Uint8Array(builtShstr.length + bytes.length);
    next.set(builtShstr);
    next.set(bytes, offset);
    builtShstr = next;
    return offset;
  }

  for (let i = 0; i < sections.length; i += 1) {
    const section = sections[i];
    if (section.nameOffset !== undefined) {
      nameOffset[i + 1] = section.nameOffset;
    } else if (!options.shstrBytes && (section.name || section.nameBytes)) {
      const bytes = section.nameBytes ?? cstr(section.name!);
      const terminated = bytes[bytes.length - 1] === 0 ? bytes : concat([bytes, new Uint8Array([0])]);
      nameOffset[i + 1] = appendName(terminated);
    }
  }

  const inferredShstr = sections.findIndex((section) => section.type === 3) + 1;
  const shstrIndex = options.shstrIndex === undefined
    ? inferredShstr
    : options.shstrIndex;

  const offsets = new Array<number>(sections.length + 1).fill(0);
  let cursor = dataOffset;
  for (let i = 0; i < sections.length; i += 1) {
    while (cursor % 8 !== 0) cursor += 1;
    offsets[i + 1] = cursor;
    cursor += (sections[i].data ?? new Uint8Array()).length;
  }

  const bytes = new Uint8Array(options.truncate ?? cursor);
  const view = new DataView(bytes.buffer);

  bytes.set([0x7f, 0x45, 0x4c, 0x46, bits === 32 ? 1 : 2, littleEndian ? 1 : 2, 1]);
  view.setUint16(16, 1, littleEndian);
  view.setUint16(18, 0x3e, littleEndian);
  view.setUint32(20, 1, littleEndian);

  if (bits === 32) {
    view.setUint32(32, sectionHeaderOffset, littleEndian);
    view.setUint16(40, ehsize, littleEndian);
    view.setUint16(46, shentsize, littleEndian);
    view.setUint16(48, count, littleEndian);
    view.setUint16(50, shstrIndex ?? 0, littleEndian);
  } else {
    view.setBigUint64(40, BigInt(sectionHeaderOffset), littleEndian);
    view.setUint16(52, ehsize, littleEndian);
    view.setUint16(58, shentsize, littleEndian);
    view.setUint16(60, count, littleEndian);
    view.setUint16(62, shstrIndex ?? 0, littleEndian);
  }

  for (let i = 0; i < sections.length; i += 1) {
    const section = sections[i];
    const index = i + 1;
    const shoff = sectionHeaderOffset + index * shentsize;
    const sectionData = index === shstrIndex
      ? (section.data ?? options.shstrBytes ?? builtShstr)
      : (section.data ?? new Uint8Array());
    if (!section.data && sectionData.length > 0 && offsets[index] < bytes.length) {
      bytes.set(sectionData.subarray(0, bytes.length - offsets[index]), offsets[index]);
    } else if (section.data && offsets[index] < bytes.length) {
      bytes.set(section.data.subarray(0, bytes.length - offsets[index]), offsets[index]);
    }

    view.setUint32(shoff, nameOffset[index] === -1 ? 0 : nameOffset[index], littleEndian);
    view.setUint32(shoff + 4, section.type ?? 1, littleEndian);

    if (bits === 32) {
      view.setUint32(shoff + 16, section.offsetOverride ?? offsets[index], littleEndian);
      view.setUint32(shoff + 20, section.sizeOverride ?? sectionData.length, littleEndian);
      view.setUint32(shoff + 24, section.link ?? 0, littleEndian);
      view.setUint32(shoff + 28, section.info ?? 0, littleEndian);
      view.setUint32(shoff + 32, 1, littleEndian);
      view.setUint32(shoff + 36, section.entrySize ?? 0, littleEndian);
    } else {
      view.setBigUint64(shoff + 24, BigInt(section.offsetOverride ?? offsets[index]), littleEndian);
      view.setBigUint64(shoff + 32, BigInt(section.sizeOverride ?? sectionData.length), littleEndian);
      view.setUint32(shoff + 40, section.link ?? 0, littleEndian);
      view.setUint32(shoff + 44, section.info ?? 0, littleEndian);
      view.setBigUint64(shoff + 48, 1n, littleEndian);
      view.setBigUint64(shoff + 56, BigInt(section.entrySize ?? 0), littleEndian);
    }
  }

  return {
    bytes,
    sectionHeaderOffset,
    nameOffset,
    dataOffset: offsets,
  };
}

function symbol(name: number, bits: 32 | 64 = 32): Uint8Array {
  const size = bits === 32 ? 16 : 24;
  const bytes = new Uint8Array(size);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, name, true);
  if (bits === 32) view.setUint16(14, 1, true);
  else view.setUint16(6, 1, true);
  return bytes;
}

it('parses', () => {
  const x = new Uint8Array(20);
  x.set([127, 69, 76, 70, 1, 1]);
  expect(parseHeader(x).bits).toBe(32);
});

it('returns an empty string for string table index 0', () => {
  const table = ElfStringTable.create(0, new Uint8Array([0, 97, 0]));
  const result = table.lookup(0);
  expect(result.ok).toBe(true);
  if (!result.ok) throw new Error('expected index 0 to succeed');
  expect(result.text).toBe('');
  expect(result.bytes).toEqual(new Uint8Array());
  expect(result.validUtf8).toBe(true);
});

it('returns an empty string for string table index 0 in a zero-size table', () => {
  const table = ElfStringTable.create(0, new Uint8Array(0));
  const result = table.lookup(0);
  expect(result.ok).toBe(true);
  if (!result.ok) throw new Error('expected index 0 in an empty table to succeed');
  expect(result.text).toBe('');
  expect(result.bytes).toEqual(new Uint8Array());
});

it('accepts a string whose NUL terminator is the final view byte', () => {
  const table = ElfStringTable.create(0, new Uint8Array([0, 97, 98, 0]));
  expect(table.getString(1)).toBe('ab');
  expect(table.getString(3)).toBe('');
});

it('rejects a string without an in-table NUL terminator', () => {
  const table = ElfStringTable.create(0, new Uint8Array([0, 102, 111, 111]));
  const result = table.lookup(1);
  expect(result.ok).toBe(false);
  if (result.ok) throw new Error('expected unterminated lookup to fail');
  expect(result.error).toBe('unterminated-string');
  expect(table.getString(1)).toBeNull();
});

it('rejects indexes outside the bounded string table view', () => {
  const table = ElfStringTable.create(0, new Uint8Array([0, 97, 0]));
  expect(table.lookup(3)).toMatchObject({ ok: false, error: 'index-out-of-bounds' });
  expect(table.lookup(4)).toMatchObject({ ok: false, error: 'index-out-of-bounds' });
  expect(table.lookup(-1)).toMatchObject({ ok: false, error: 'index-out-of-bounds' });
});

it('preserves non-UTF-8 bytes and reports replacement text explicitly', () => {
  const table = ElfStringTable.create(0, new Uint8Array([0, 0xff, 0x61, 0]));
  const result = table.lookup(1);
  expect(result.ok).toBe(true);
  if (!result.ok) throw new Error('expected non-UTF-8 lookup to succeed');
  expect(result.bytes).toEqual(new Uint8Array([0xff, 0x61]));
  expect(result.text).toBe('�a');
  expect(result.validUtf8).toBe(false);
});

it('uses section and symbol links to distinguish multiple string tables', () => {
  const shstr = concat([new Uint8Array([0]), cstr('.shstr'), cstr('.str1'), cstr('.str2'), cstr('.sym1'), cstr('.sym2')]);
  const str1 = concat([new Uint8Array([0]), cstr('first'), cstr('shared')]);
  const str2 = concat([new Uint8Array([0]), cstr('second'), cstr('shared')]);
  const image = makeElf([
    { type: 3, data: shstr, nameOffset: 1 },
    { type: 3, data: str1, nameOffset: 8 },
    { type: 3, data: str2, nameOffset: 14 },
    { type: 2, data: concat([symbol(1), symbol(7)]), link: 2, entrySize: 16, nameOffset: 20 },
    { type: 2, data: concat([symbol(1), symbol(8)]), link: 3, entrySize: 16, nameOffset: 26 },
  ]);
  const elf = parseElf(image.bytes);

  expect(elf.sections[1].name).toBe('.shstr');
  expect(elf.sections[2].name).toBe('.str1');
  expect(elf.sections[3].name).toBe('.str2');
  expect(elf.symbolTables[0].linkedStringTableSection).toBe(2);
  expect(elf.symbolTables[1].linkedStringTableSection).toBe(3);
  expect(elf.symbolTables.map((symbolTable) => symbolTable.symbols[1].name)).toEqual(['shared', 'shared']);
  expect(elf.symbolTables[0].symbols[0].name).toBe('first');
  expect(elf.symbolTables[1].symbols[0].name).toBe('second');
  expect(elf.symbolsByName.get('shared')).toHaveLength(2);
});

it('does not use a non-string-table sh_link as a symbol name table', () => {
  const shstr = concat([new Uint8Array([0]), cstr('.shstr'), cstr('.other'), cstr('.symtab')]);
  const other = new Uint8Array([1, 2, 3, 4]);
  const image = makeElf([
    { type: 3, data: shstr, nameOffset: 1 },
    { type: 1, data: other, nameOffset: 8 },
    { type: 2, data: symbol(0), link: 2, entrySize: 16, nameOffset: 15 },
  ]);

  const elf = parseElf(image.bytes);
  expect(elf.symbolTables[0].linkedStringTableSection).toBeNull();
  expect(elf.symbols[0].name).toBeNull();
  expect(elf.symbols[0].nameError).toBe('string-table-wrong-type');
  expect(elf.symbolsByName.size).toBe(0);
});

it('does not let an unterminated section name read the following section', () => {
  const shstr = concat([
    new Uint8Array([0]),
    cstr('.shstr'),
    cstr('.str'),
    cstr('.symtab'),
    encoder.encode('evil-has-no-nul'),
  ]);
  const evilOffset = shstr.length - 'evil-has-no-nul'.length;
  const str = concat([new Uint8Array([0]), cstr('real-symbol')]);
  const followingData = concat([encoder.encode('NEXT-SECTION'), new Uint8Array([0])]);
  const image = makeElf([
    { type: 3, data: shstr, nameOffset: 1 },
    { type: 3, data: str, nameOffset: 8 },
    { type: 2, data: symbol(1), link: 2, entrySize: 16, nameOffset: 13 },
    { type: 1, data: followingData, nameOffset: evilOffset },
  ]);

  const elf = parseElf(image.bytes);
  expect(elf.sections[1].name).toBe('.shstr');
  expect(elf.sections[3].name).toBe('.symtab');
  expect(elf.sections[4].name).toBeNull();
  expect(elf.sections[4].nameError).toBe('unterminated-string');
  expect(elf.sections[4].nameBytes).toBeNull();
  expect(elf.symbols[0].name).toBe('real-symbol');
});

it('omits truncated string tables and rejects symbols in truncated symbol sections', () => {
  const shstr = concat([new Uint8Array([0]), cstr('.shstr'), cstr('.str'), cstr('.symtab')]);
  const str = concat([new Uint8Array([0]), cstr('symbol')]);
  const image = makeElf([
    { type: 3, data: shstr, nameOffset: 1 },
    { type: 3, data: str, nameOffset: 8 },
    { type: 2, data: symbol(1), sizeOverride: 32, link: 2, entrySize: 16, nameOffset: 13 },
  ]);

  const elf = parseElf(image.bytes);
  expect(elf.stringTables.has(2)).toBe(true);
  expect(elf.sections.map((section) => section.name)).toEqual(['', '.shstr', '.str', '.symtab']);
  expect(elf.symbolTables[0].error).toBe('section-out-of-bounds');
  expect(elf.symbolTables[0].symbols).toEqual([]);
  expect(elf.symbols).toEqual([]);
  expect(elf.symbolsByName.has('symbol')).toBe(false);
});

it('treats a string-table section extending past EOF as unavailable', () => {
  const image = makeElf([
    { type: 3, data: new Uint8Array([0, 97, 0]), sizeOverride: 64 },
  ], { shstrIndex: 1 });

  const elf = parseElf(image.bytes);
  expect(elf.stringTables.has(1)).toBe(false);
  expect(elf.sections[1].name).toBeNull();
  expect(elf.sections[1].nameError).toBe('string-table-unavailable');
});

it('does not treat a non-string-table e_shstrndx as the section-name table', () => {
  const image = makeElf([
    { type: 1, data: new Uint8Array([1, 2, 3]) },
  ], { shstrIndex: 1 });

  const elf = parseElf(image.bytes);
  expect(elf.sections[1].name).toBeNull();
  expect(elf.sections[1].nameError).toBe('string-table-unavailable');
});

it('throws when the section header table itself is truncated', () => {
  const image = makeElf([
    { type: 3, data: new Uint8Array([0]) },
  ]);
  const truncated = image.bytes.subarray(0, image.sectionHeaderOffset + 42);
  expect(() => parseElf(truncated)).toThrow(/section header table/);
});

it('keeps invalid UTF-8 bytes but does not index a replacement symbol name', () => {
  const shstr = concat([
    new Uint8Array([0]),
    new Uint8Array([0xff]),
    cstr('.shstr'),
    cstr('.str'),
    cstr('.symtab'),
  ]);
  const str = concat([new Uint8Array([0, 0xff, 0]), cstr('valid')]);
  const image = makeElf([
    { type: 3, data: shstr, nameOffset: 1 },
    { type: 3, data: str, nameOffset: 11 },
    { type: 2, data: concat([symbol(1), symbol(3)]), link: 2, entrySize: 16, nameOffset: 16 },
  ]);

  const elf = parseElf(image.bytes);
  expect(elf.sections[1].name).toBe('�.shstr');
  expect(elf.sections[1].nameValidUtf8).toBe(false);
  expect(elf.sections[1].nameBytes).toEqual(
    Uint8Array.from([0xff, ...encoder.encode('.shstr')]),
  );

  const invalid = elf.symbolTables[0].symbols[0];
  const valid = elf.symbolTables[0].symbols[1];
  expect(invalid.name).toBe('�');
  expect(invalid.nameBytes).toEqual(new Uint8Array([0xff]));
  expect(invalid.nameValidUtf8).toBe(false);
  expect(valid.name).toBe('valid');
  expect([...elf.symbolsByName.keys()]).toEqual(['valid']);
});

it('does not put index 0 or failed symbol names in the symbol name index', () => {
  const shstr = concat([new Uint8Array([0]), cstr('.shstr'), cstr('.str'), cstr('.symtab')]);
  const str = new Uint8Array([0, 102, 97, 105, 108]);
  const image = makeElf([
    { type: 3, data: shstr, nameOffset: 1 },
    { type: 3, data: str, nameOffset: 8 },
    { type: 2, data: concat([symbol(0), symbol(1)]), link: 2, entrySize: 16, nameOffset: 13 },
  ]);

  const elf = parseElf(image.bytes);
  expect(elf.symbols[0].name).toBe('');
  expect(elf.symbols[1].name).toBeNull();
  expect(elf.symbols[1].nameError).toBe('unterminated-string');
  expect(elf.symbolsByName.size).toBe(0);
});

it.each([32, 64] as const)('uses sh_link for bounded symbol names in ELF%i', (bits) => {
  const entrySize = bits === 64 ? 24 : 16;
  const shstr = concat([new Uint8Array([0]), cstr('.shstr'), cstr('.linked'), cstr('.symbols')]);
  const linked = concat([new Uint8Array([0]), cstr('arch-name')]);
  const image = makeElf([
    { type: 3, data: shstr, nameOffset: 1 },
    { type: 3, data: linked },
    { type: 2, data: symbol(1, bits), link: 2, entrySize },
  ], { bits });

  const elf = parseElf(image.bytes);
  expect(elf.header.bits).toBe(bits);
  expect(elf.symbolTables[0].linkedStringTableSection).toBe(2);
  expect(elf.symbols[0].name).toBe('arch-name');
  expect(elf.symbolsByName.get('arch-name')).toHaveLength(1);
});
