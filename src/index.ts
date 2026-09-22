export type ElfBits = 32 | 64;

export interface ElfHeader {
  bits: ElfBits;
  littleEndian: boolean;
  type: number;
  machine: number;
}

export interface ParsedElfHeader extends ElfHeader {
  version: number;
  entry: bigint;
  programHeaderOffset: bigint;
  sectionHeaderOffset: bigint;
  flags: number;
  elfHeaderSize: number;
  programHeaderEntrySize: number;
  programHeaderCount: number;
  sectionHeaderEntrySize: number;
  sectionHeaderCount: number;
  sectionNameStringTableIndex: number;
}

export const SHT_SYMTAB = 2;
export const SHT_STRTAB = 3;
export const SHT_NOBITS = 8;
export const SHT_DYNSYM = 11;

const SHN_XINDEX = 0xffff;

export type ElfStringLookupErrorCode =
  | 'index-out-of-bounds'
  | 'unterminated-string';

export type ElfNameErrorCode =
  | ElfStringLookupErrorCode
  | 'string-table-unavailable'
  | 'string-table-wrong-type';

export interface StringLookupSuccess {
  ok: true;
  index: number;
  bytes: Uint8Array;
  text: string;
  validUtf8: boolean;
}

export interface StringLookupFailure {
  ok: false;
  index: number;
  error: ElfStringLookupErrorCode;
}

export type StringLookupResult = StringLookupSuccess | StringLookupFailure;

export interface DecodedElfString {
  bytes: Uint8Array;
  text: string;
  validUtf8: boolean;
}

const strictUtf8 = new TextDecoder('utf-8', { fatal: true });
const replacementUtf8 = new TextDecoder('utf-8');

/**
 * Decode bounded string-table bytes. Invalid UTF-8 is preserved byte-for-byte
 * in `bytes`, while `text` uses the standard U+FFFD replacement policy.
 */
export function decodeElfString(bytes: Uint8Array): DecodedElfString {
  try {
    return { bytes, text: strictUtf8.decode(bytes), validUtf8: true };
  } catch {
    return {
      bytes,
      text: replacementUtf8.decode(bytes),
      validUtf8: false,
    };
  }
}

/**
 * A string table backed by a bounded view. The view's length is the section
 * size; lookups can never read following sections.
 */
export class ElfStringTable {
  readonly sectionIndex: number;
  readonly data: Uint8Array;

  private constructor(sectionIndex: number, data: Uint8Array) {
    this.sectionIndex = sectionIndex;
    this.data = data;
  }

  static create(sectionIndex: number, sectionData: Uint8Array): ElfStringTable {
    return new ElfStringTable(sectionIndex, sectionData);
  }

  get size(): number {
    return this.data.length;
  }

  lookup(index: number): StringLookupResult {
    if (index === 0) {
      const empty = new Uint8Array(0);
      return {
        ok: true,
        index,
        bytes: empty,
        text: '',
        validUtf8: true,
      };
    }

    if (!Number.isInteger(index) || index < 0 || index >= this.data.length) {
      return { ok: false, index, error: 'index-out-of-bounds' };
    }

    let end = index;
    while (end < this.data.length && this.data[end] !== 0) {
      end += 1;
    }

    if (end === this.data.length) {
      return { ok: false, index, error: 'unterminated-string' };
    }

    const bytes = this.data.subarray(index, end);
    const decoded = decodeElfString(bytes);
    return { ok: true, index, ...decoded };
  }

  /** Returns lossy UTF-8 text, or null for an out-of-bounds/unterminated index. */
  getString(index: number): string | null {
    const result = this.lookup(index);
    return result.ok ? result.text : null;
  }
}

interface RawElfSection {
  index: number;
  nameOffset: number;
  type: number;
  flags: bigint;
  addr: bigint;
  offset: bigint;
  size: bigint;
  link: number;
  info: number;
  addralign: bigint;
  entrySize: bigint;
  dataError?: 'section-out-of-bounds';
}

export interface ElfSection {
  index: number;
  nameOffset: number;
  type: number;
  flags: bigint;
  addr: bigint;
  offset: bigint;
  size: bigint;
  link: number;
  info: number;
  addralign: bigint;
  entrySize: bigint;
  name: string | null;
  nameBytes: Uint8Array | null;
  nameValidUtf8: boolean | null;
  nameError?: ElfNameErrorCode;
  dataError?: 'section-out-of-bounds';
}

export interface ElfSymbol {
  symbolTableSection: number;
  index: number;
  nameOffset: number;
  name: string | null;
  nameBytes: Uint8Array | null;
  nameValidUtf8: boolean | null;
  nameError?: ElfNameErrorCode;
  value: bigint;
  size: bigint;
  info: number;
  other: number;
  sectionIndex: number;
  binding: number;
  type: number;
}

export type ElfSymbolTableErrorCode =
  | 'section-out-of-bounds'
  | 'invalid-symbol-entry-size';

export type ElfSymbolTableWarning = 'partial-final-symbol';

export interface ElfSymbolTable {
  sectionIndex: number;
  linkedStringTableSection: number | null;
  symbols: ElfSymbol[];
  error?: ElfSymbolTableErrorCode;
  warning?: ElfSymbolTableWarning;
}

export interface ParsedElf {
  header: ParsedElfHeader;
  sections: ElfSection[];
  stringTables: Map<number, ElfStringTable>;
  symbolTables: ElfSymbolTable[];
  symbols: ElfSymbol[];
  /** Only non-empty, validly-encoded names are inserted into this index. */
  symbolsByName: Map<string, ElfSymbol[]>;
}

interface ResolvedName {
  name: string | null;
  nameBytes: Uint8Array | null;
  nameValidUtf8: boolean | null;
  nameError?: ElfNameErrorCode;
}

function failedName(error: ElfNameErrorCode): ResolvedName {
  return { name: null, nameBytes: null, nameValidUtf8: null, nameError: error };
}

function resolveName(
  index: number,
  table: ElfStringTable | undefined,
  missingReason: ElfNameErrorCode = 'string-table-unavailable',
): ResolvedName {
  if (!table) return failedName(missingReason);

  const result = table.lookup(index);
  if (!result.ok) return failedName(result.error);

  return {
    name: result.text,
    nameBytes: result.bytes,
    nameValidUtf8: result.validUtf8,
  };
}

function assertRange(
  data: Uint8Array,
  offset: bigint,
  size: bigint,
  context: string,
): void {
  if (offset < 0n || size < 0n || offset + size > BigInt(data.length)) {
    throw new Error(`truncated ELF: ${context}`);
  }
}

function dataView(data: Uint8Array): DataView {
  return new DataView(data.buffer, data.byteOffset, data.byteLength);
}

function readU16(view: DataView, offset: number, littleEndian: boolean): number {
  return view.getUint16(offset, littleEndian);
}

function readU32(view: DataView, offset: number, littleEndian: boolean): number {
  return view.getUint32(offset, littleEndian);
}

function readU64(view: DataView, offset: number, littleEndian: boolean): bigint {
  return view.getBigUint64(offset, littleEndian);
}

export function parseHeader(data: Uint8Array): ElfHeader {
  if (data.length < 20) throw new Error('not elf');
  if (data[0] !== 0x7f || data[1] !== 0x45 || data[2] !== 0x4c || data[3] !== 0x46) {
    throw new Error('not elf');
  }

  const bitsValue = data[4] === 1 ? 32 : data[4] === 2 ? 64 : 0;
  if (bitsValue !== 32 && bitsValue !== 64) throw new Error('invalid ELF class');
  if (data[5] !== 1 && data[5] !== 2) throw new Error('invalid ELF data encoding');

  const bits = bitsValue as ElfBits;
  const littleEndian = data[5] === 1;
  const view = dataView(data);
  return {
    bits,
    littleEndian,
    type: readU16(view, 16, littleEndian),
    machine: readU16(view, 18, littleEndian),
  };
}

function parseFullHeader(data: Uint8Array): ParsedElfHeader {
  const base = parseHeader(data);
  const headerSize = base.bits === 32 ? 52 : 64;
  assertRange(data, 0n, BigInt(headerSize), 'ELF header');

  const view = dataView(data);
  const le = base.littleEndian;
  const common = {
    ...base,
    version: readU32(view, 20, le),
    flags: 0,
    elfHeaderSize: 0,
    programHeaderEntrySize: 0,
    programHeaderCount: 0,
    sectionHeaderEntrySize: 0,
    sectionHeaderCount: 0,
    sectionNameStringTableIndex: 0,
  };

  if (base.bits === 32) {
    return {
      ...common,
      entry: BigInt(readU32(view, 24, le)),
      programHeaderOffset: BigInt(readU32(view, 28, le)),
      sectionHeaderOffset: BigInt(readU32(view, 32, le)),
      flags: readU32(view, 36, le),
      elfHeaderSize: readU16(view, 40, le),
      programHeaderEntrySize: readU16(view, 42, le),
      programHeaderCount: readU16(view, 44, le),
      sectionHeaderEntrySize: readU16(view, 46, le),
      sectionHeaderCount: readU16(view, 48, le),
      sectionNameStringTableIndex: readU16(view, 50, le),
    };
  }

  return {
    ...common,
    entry: readU64(view, 24, le),
    programHeaderOffset: readU64(view, 32, le),
    sectionHeaderOffset: readU64(view, 40, le),
    flags: readU32(view, 48, le),
    elfHeaderSize: readU16(view, 52, le),
    programHeaderEntrySize: readU16(view, 54, le),
    programHeaderCount: readU16(view, 56, le),
    sectionHeaderEntrySize: readU16(view, 58, le),
    sectionHeaderCount: readU16(view, 60, le),
    sectionNameStringTableIndex: readU16(view, 62, le),
  };
}

function readSection(
  data: Uint8Array,
  index: number,
  position: bigint,
  bits: ElfBits,
  littleEndian: boolean,
): RawElfSection {
  const view = dataView(data);
  const at = Number(position);

  const nameOffset = readU32(view, at, littleEndian);
  const type = readU32(view, at + 4, littleEndian);

  if (bits === 32) {
    return {
      index,
      nameOffset,
      type,
      flags: BigInt(readU32(view, at + 8, littleEndian)),
      addr: BigInt(readU32(view, at + 12, littleEndian)),
      offset: BigInt(readU32(view, at + 16, littleEndian)),
      size: BigInt(readU32(view, at + 20, littleEndian)),
      link: readU32(view, at + 24, littleEndian),
      info: readU32(view, at + 28, littleEndian),
      addralign: BigInt(readU32(view, at + 32, littleEndian)),
      entrySize: BigInt(readU32(view, at + 36, littleEndian)),
    };
  }

  return {
    index,
    nameOffset,
    type,
    flags: readU64(view, at + 8, littleEndian),
    addr: readU64(view, at + 16, littleEndian),
    offset: readU64(view, at + 24, littleEndian),
    size: readU64(view, at + 32, littleEndian),
    link: readU32(view, at + 40, littleEndian),
    info: readU32(view, at + 44, littleEndian),
    addralign: readU64(view, at + 48, littleEndian),
    entrySize: readU64(view, at + 56, littleEndian),
  };
}

function readSectionHeaders(
  data: Uint8Array,
  header: ParsedElfHeader,
): { sections: RawElfSection[]; sectionNameStringTableIndex: number } {
  if (header.sectionHeaderOffset === 0n || header.sectionHeaderCount === 0) {
    return { sections: [], sectionNameStringTableIndex: -1 };
  }

  const fixedSize = header.bits === 32 ? 40 : 64;
  if (header.sectionHeaderEntrySize < fixedSize) {
    throw new Error('truncated ELF: section header entry');
  }

  let count = header.sectionHeaderCount;
  let nameIndex = header.sectionNameStringTableIndex;

  // ELF extended section numbering stores the real values in section zero.
  if (count === 0 || nameIndex === SHN_XINDEX) {
    assertRange(
      data,
      header.sectionHeaderOffset,
      BigInt(fixedSize),
      'first section header',
    );
    const first = readSection(
      data,
      0,
      header.sectionHeaderOffset,
      header.bits,
      header.littleEndian,
    );

    if (count === 0) {
      if (first.size < 1n || first.size > BigInt(Number.MAX_SAFE_INTEGER)) {
        throw new Error('invalid ELF section count');
      }
      count = Number(first.size);
    }
    if (nameIndex === SHN_XINDEX) nameIndex = first.link;
  }

  if (count === 0) return { sections: [], sectionNameStringTableIndex: -1 };

  const stride = BigInt(header.sectionHeaderEntrySize);
  assertRange(
    data,
    header.sectionHeaderOffset,
    BigInt(count) * stride,
    'section header table',
  );

  const sections: RawElfSection[] = [];
  for (let index = 0; index < count; index += 1) {
    sections.push(
      readSection(
        data,
        index,
        header.sectionHeaderOffset + BigInt(index) * stride,
        header.bits,
        header.littleEndian,
      ),
    );
  }

  if (nameIndex < 0 || nameIndex >= count) nameIndex = -1;
  return { sections, sectionNameStringTableIndex: nameIndex };
}

function markTruncatedSections(sections: RawElfSection[], fileSize: number): void {
  const length = BigInt(fileSize);
  for (const section of sections) {
    if (section.type === SHT_NOBITS) continue;
    if (section.offset + section.size > length) {
      section.dataError = 'section-out-of-bounds';
    }
  }
}

function sectionView(data: Uint8Array, section: RawElfSection): Uint8Array {
  return data.subarray(
    Number(section.offset),
    Number(section.offset + section.size),
  );
}

function parseSymbolTable(
  data: Uint8Array,
  section: RawElfSection,
  rawSections: RawElfSection[],
  stringTables: Map<number, ElfStringTable>,
  bits: ElfBits,
  littleEndian: boolean,
): ElfSymbolTable {
  const linkedRaw = section.link < rawSections.length ? rawSections[section.link] : undefined;
  const linkedTable =
    linkedRaw?.type === SHT_STRTAB ? stringTables.get(section.link) : undefined;

  const table: ElfSymbolTable = {
    sectionIndex: section.index,
    linkedStringTableSection: linkedTable ? section.link : null,
    symbols: [],
  };

  if (section.dataError) {
    table.error = 'section-out-of-bounds';
    return table;
  }

  const fixedEntrySize = bits === 32 ? 16 : 24;
  const stride = section.entrySize === 0n
    ? fixedEntrySize
    : Number(section.entrySize);

  if (!Number.isSafeInteger(stride) || stride < fixedEntrySize) {
    table.error = 'invalid-symbol-entry-size';
    return table;
  }

  const strideBytes = BigInt(stride);
  const entryCount = section.size / strideBytes;
  if (section.size % strideBytes !== 0n) {
    table.warning = 'partial-final-symbol';
  }
  if (entryCount > BigInt(Number.MAX_SAFE_INTEGER)) {
    table.error = 'invalid-symbol-entry-size';
    return table;
  }

  const view = sectionView(data, section);
  const viewReader = dataView(view);

  for (let index = 0; index < Number(entryCount); index += 1) {
    const at = index * stride;
    const nameOffset = readU32(viewReader, at, littleEndian);

    let value: bigint;
    let size: bigint;
    let info: number;
    let other: number;
    let sectionIndex: number;

    if (bits === 32) {
      value = BigInt(readU32(viewReader, at + 4, littleEndian));
      size = BigInt(readU32(viewReader, at + 8, littleEndian));
      info = view[at + 12];
      other = view[at + 13];
      sectionIndex = readU16(viewReader, at + 14, littleEndian);
    } else {
      info = view[at + 4];
      other = view[at + 5];
      sectionIndex = readU16(viewReader, at + 6, littleEndian);
      value = readU64(viewReader, at + 8, littleEndian);
      size = readU64(viewReader, at + 16, littleEndian);
    }

    let resolved: ResolvedName;
    if (!linkedRaw) {
      resolved = failedName('string-table-unavailable');
    } else if (linkedRaw.type !== SHT_STRTAB) {
      resolved = failedName('string-table-wrong-type');
    } else {
      resolved = resolveName(nameOffset, linkedTable);
    }

    table.symbols.push({
      symbolTableSection: section.index,
      index,
      nameOffset,
      ...resolved,
      value,
      size,
      info,
      other,
      sectionIndex,
      binding: info >>> 4,
      type: info & 0x0f,
    });
  }

  return table;
}

export function parseElf(input: Uint8Array): ParsedElf {
  const data = input instanceof Uint8Array ? input : new Uint8Array(input);
  const header = parseFullHeader(data);
  const { sections: rawSections, sectionNameStringTableIndex } =
    readSectionHeaders(data, header);

  markTruncatedSections(rawSections, data.length);

  const stringTables = new Map<number, ElfStringTable>();
  for (const section of rawSections) {
    if (section.type === SHT_STRTAB && !section.dataError) {
      stringTables.set(
        section.index,
        ElfStringTable.create(section.index, sectionView(data, section)),
      );
    }
  }

  const sectionNameTable =
    rawSections[sectionNameStringTableIndex]?.type === SHT_STRTAB
      ? stringTables.get(sectionNameStringTableIndex)
      : undefined;
  const sections: ElfSection[] = rawSections.map((section) => ({
    ...section,
    ...resolveName(section.nameOffset, sectionNameTable),
  }));

  const symbolTables: ElfSymbolTable[] = [];
  for (const section of rawSections) {
    if (section.type !== SHT_SYMTAB && section.type !== SHT_DYNSYM) continue;
    symbolTables.push(
      parseSymbolTable(
        data,
        section,
        rawSections,
        stringTables,
        header.bits,
        header.littleEndian,
      ),
    );
  }

  const symbols = symbolTables.flatMap((table) => table.symbols);
  const symbolsByName = new Map<string, ElfSymbol[]>();
  for (const symbol of symbols) {
    if (symbol.name && symbol.nameValidUtf8 === true) {
      const matches = symbolsByName.get(symbol.name);
      if (matches) matches.push(symbol);
      else symbolsByName.set(symbol.name, [symbol]);
    }
  }

  return {
    header,
    sections,
    stringTables,
    symbolTables,
    symbols,
    symbolsByName,
  };
}
