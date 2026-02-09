---
title: 폰트 라이브러리 취약점 발견 및 분석 with Fuzzing
description: HSPACE Knights Frontier의 폰트 라이브러리 취약점 연구 내용입니다.
author: 이재영(Finder)
date: 2026-02-04
tags: [Fuzzing, Font, CVE-2026-22693]
categories: [Vulnerability Research, Fuzzing]
math: true
mermaid: false
pin: false
image: /assets/img/2026fontfuzzing/thumbnail.jpg
---

## 목차
1. [Part 1. FreeType DoS 취약점 발견 및 분석](#part-1-freetype-dos-취약점-발견-및-분석)
2. [Part 2. HarfBuzz Null Pointer Dereference 취약점 발견 및 분석](#part-2-harfbuzz-null-pointer-dereference-취약점-발견-및-분석)


이번 글에서는 **LibFuzzer**를 이용하여 **FreeType**과 **HarfBuzz** 라이브러리를 대상으로 퍼징을 수행한 과정과 발견한 취약점을 정리해 보겠습니다.

해당 프로젝트는 HSPACE Knights Frontier 분들이 진행한 연구이며, 박정우님과 조준하님께서 본 글을 작성해 주셨습니다.

## Part 1. FreeType DoS 취약점 발견 및 분석


### 1. 퍼징 타겟 선정 배경

이번에 퍼징을 진행한 타겟은 **FreeType**이라는 라이브러리 프레임워크입니다.
- The FreeType Project([freetype.org](https://freetype.org/))


FreeType은 Android, Chrome, Linux 등 전 세계 수십억 대의 디바이스에서 폰트 렌더링을 담당하는 핵심 오픈소스 라이브러리로 알려져 있습니다. 다양한 폰트 포맷을 처리하면서 입력 데이터를 직접 파싱하고 복잡한 내부 로직을 수행하기 때문에, 오래전부터 많은 보안 연구자들이 집중적으로 취약점 분석을 진행해온 타겟 중 하나입니다.

최근에도 취약점 보고가 꾸준히 올라오고 있으며, GitLab을 통해 개발사와 비교적 빠르게 커뮤니케이션이 가능하다는 점도 고려하여 이번 연구 대상으로 선정하였습니다.

---

### 2. Attack Surface 분석

퍼징을 진행하기에 앞서, 저는 FreeType에 대한 Attack Surface 분석을 먼저 수행하였습니다. 분석 과정에서는 Codex를 활용하여 소스코드 전체 흐름을 확인하였고, 외부 입력(폰트 파일)이 깊게 전파되는 경로를 중심으로 Attack Surface를 다음과 같이 분류하였습니다.

#### (1) SFNT 기본 진입 경로
- `FT_New_Memory_Face → sfnt_init_face → tt_face_load_font_dir` 가 핵심 진입점입니다.  
- 대부분의 TTF/OTF 폰트가 이 경로를 거치며, 이후 테이블 파싱 로직으로 분기됩니다.  
- 실제로 가장 보편적이고 중요한 진입 경로이기 때문에 우선순위를 높게 두었습니다.

#### (2) 테이블 로딩(지연 로딩 구조)
- `tt_face_load_*` 계열 함수에서 테이블별 파싱이 진행됩니다.  
- 구조체 크기, 길이, 오프셋 검증이 제대로 되지 않는 경우 취약점이 발생하기 쉬운 구간입니다.

#### (3) CFF / CFF2 파서 및 로더
- INDEX 파싱과 CharString 인터프리터 로직이 존재합니다.  
- 스택 기반 처리와 복잡한 파싱 흐름이 결합되어 있어 메모리 취약점 위험이 높은 구간으로 판단하였습니다.

#### (4) Variations(가변 폰트)
- `fvar, avar, gvar, HVAR, VVAR` 등 다양한 테이블에서 좌표/델타 처리가 수행됩니다.  
- 산술 연산이 빈번하고 범위 체크가 중요하기 때문에 정수 오버플로우나 검증 누락 가능성을 특히 주의해서 보았습니다.

#### (5) 컬러 폰트 경로
- `COLR/CPAL/SVG/sbix` 등 컬러 폰트 관련 테이블 처리 경로입니다.  
- 특히 SVG는 외부 파서와 연동될 가능성이 있어 공격 표면이 확장될 수 있다고 판단하였습니다.

#### (6) TrueType 힌팅/VM
- `fpgm, cvt, prep` 테이블 및 TrueType VM 실행 경로입니다.  
- 연산량이 급격히 증가하여 timeout 기반의 DoS가 유발될 수 있는 민감한 구간입니다.

#### (7) Bitmap / Embedded 폰트
- `sbit, sbix` 등 비트맵 폰트 관련 경로입니다.  
- 비교적 덜 주목되는 경로에서 예외 처리나 경계 조건 문제가 발생할 수 있다고 보았습니다.

#### (8) Type1 / CID / Type42
- 포맷별 로더 경로가 별도로 존재하며, 파서/디코더에서 위험 지점이 존재할 수 있습니다.  
- 상대적으로 퍼징 커버리지가 낮아질 수 있는 영역이라 별도로 고려하였습니다.

#### (9) 스트림 / 메모리 경계 처리
- 입력 길이, seek, read 실패 처리 등 공통적인 스트림 처리 구간입니다.  
- OOB, NULL dereference 등 오류가 발생하기 쉬운 영역이어서 전체적으로 중요하게 보았습니다.

---

### 3. 하네스 설계 방향

위에서 정리한 Attack Surface를 최대한 폭넓게 커버하기 위해, 단순히 `FT_New_Memory_Face` 호출로 끝나는 형태가 아니라 여러 API 호출을 통해 다양한 경로를 실제로 실행하도록 하네스를 구성하였습니다.

> 아래 코드는 실제로 사용한 하네스/뮤테이터 코드입니다.

```c
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <algorithm>
#include <string>
#include <vector>

#include <ft2build.h>
#include FT_FREETYPE_H
#include FT_MULTIPLE_MASTERS_H
#include FT_COLOR_H
#include FT_GX_VALIDATE_H
#include FT_GLYPH_H
#include FT_BBOX_H
#include FT_OPENTYPE_VALIDATE_H
#include FT_FONT_FORMATS_H
#include FT_TYPE1_TABLES_H
#include FT_CID_H
#include FT_BDF_H
#include FT_WINFONTS_H
#include FT_SFNT_NAMES_H
#include FT_TRUETYPE_TAGS_H
#include FT_TRUETYPE_TABLES_H

#include <woff2/decode.h>
#include <woff2/encode.h>

extern "C" size_t LLVMFuzzerMutate(uint8_t* data, size_t size, size_t max_size);

static uint32_t fuzz_u32(const uint8_t* data, size_t size, size_t* off) {
  uint32_t v = 0;
  for (int i = 0; i < 4; ++i) {
    v <<= 8;
    if (*off < size) v |= data[(*off)++];
  }
  return v;
}

static uint16_t read_be16(const uint8_t* p) {
  return (uint16_t)((p[0] << 8) | p[1]);
}

static uint32_t read_be32(const uint8_t* p) {
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
         ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

struct Rand32 {
  uint32_t s;
  uint32_t next() {
    s ^= s << 13;
    s ^= s >> 17;
    s ^= s << 5;
    return s;
  }
  size_t uniform(size_t n) {
    return n ? (size_t)(next() % n) : 0;
  }
};

static void mutate_region(uint8_t* data, size_t size, size_t off, size_t len, Rand32* rng) {
  if (!len || off >= size) return;
  if (off + len > size) len = size - off;
  if (!len) return;

  size_t pos = off + rng->uniform(len);
  switch (rng->uniform(4)) {
    case 0:
      data[pos] ^= (uint8_t)(1u << (rng->uniform(8)));
      break;
    case 1:
      data[pos] = (uint8_t)(rng->uniform(2) ? 0x00 : 0xFF);
      break;
    case 2:
      data[pos] = (uint8_t)(data[pos] + (rng->uniform(2) ? 1 : 255));
      break;
    default:
      if (len >= 4) {
        size_t src = off + rng->uniform(len - 1);
        size_t dst = off + rng->uniform(len - 1);
        size_t count = 1 + rng->uniform(4);
        if (src + count > off + len) count = off + len - src;
        if (dst + count > off + len) count = off + len - dst;
        memmove(data + dst, data + src, count);
      }
      break;
  }
}

static bool mutate_sfnt(uint8_t* data, size_t size, Rand32* rng) {
  if (size < 12) return false;
  uint16_t num_tables = read_be16(data + 4);
  size_t dir_size = 12 + (size_t)num_tables * 16;
  if (dir_size > size || num_tables == 0) return false;

  size_t idx = rng->uniform(num_tables);
  const uint8_t* rec = data + 12 + idx * 16;
  uint32_t off = read_be32(rec + 8);
  uint32_t len = read_be32(rec + 12);
  if (off >= size || len == 0) return false;
  if ((size_t)off + len > size) len = (uint32_t)(size - off);
  mutate_region(data, size, off, len, rng);
  return true;
}

static bool mutate_woff(uint8_t* data, size_t size, Rand32* rng) {
  if (size < 44) return false;
  uint16_t num_tables = read_be16(data + 12);
  size_t dir_size = 44 + (size_t)num_tables * 20;
  if (dir_size > size || num_tables == 0) return false;

  uint32_t meta_offset = read_be32(data + 28);
  uint32_t meta_length = read_be32(data + 32);
  if (meta_length && meta_offset < size && meta_offset + meta_length <= size) {
    mutate_region(data, size, meta_offset, meta_length, rng);
    return true;
  }

  size_t idx = rng->uniform(num_tables);
  const uint8_t* rec = data + 44 + idx * 20;
  uint32_t off = read_be32(rec + 4);
  uint32_t len = read_be32(rec + 8);
  if (off >= size || len == 0) return false;
  if ((size_t)off + len > size) len = (uint32_t)(size - off);
  mutate_region(data, size, off, len, rng);
  return true;
}

static bool mutate_woff2(uint8_t* data, size_t size, Rand32* rng) {
  if (size < 48) return false;
  uint32_t meta_offset = read_be32(data + 24);
  uint32_t meta_length = read_be32(data + 28);
  if (meta_length && meta_offset < size && meta_offset + meta_length <= size) {
    mutate_region(data, size, meta_offset, meta_length, rng);
    return true;
  }

  uint32_t priv_offset = read_be32(data + 36);
  uint32_t priv_length = read_be32(data + 40);
  if (priv_length && priv_offset < size && priv_offset + priv_length <= size) {
    mutate_region(data, size, priv_offset, priv_length, rng);
    return true;
  }

  mutate_region(data, size, 48, size - 48, rng);
  return true;
}

static bool mutate_woff2_full(uint8_t* data, size_t size, size_t max_size, Rand32* rng,
                              size_t* out_size) {
  std::string ttf;
  woff2::WOFF2StringOut out(&ttf);
  size_t max_out = std::min(woff2::kDefaultMaxSize, max_size ? max_size * 8 : woff2::kDefaultMaxSize);
  out.SetMaxSize(max_out);
  if (!woff2::ConvertWOFF2ToTTF(data, size, &out) || ttf.empty()) return false;

  std::vector<uint8_t> ttf_buf(ttf.begin(), ttf.end());
  if (!mutate_sfnt(ttf_buf.data(), ttf_buf.size(), rng)) {
    mutate_region(ttf_buf.data(), ttf_buf.size(), 0, ttf_buf.size(), rng);
  }

  size_t max_comp = woff2::MaxWOFF2CompressedSize(ttf_buf.data(), ttf_buf.size());
  if (max_comp == 0 || max_comp > max_size) return false;
  std::vector<uint8_t> comp(max_comp);
  size_t comp_len = max_comp;
  if (!woff2::ConvertTTFToWOFF2(ttf_buf.data(), ttf_buf.size(),
                                comp.data(), &comp_len)) {
    return false;
  }
  if (comp_len == 0 || comp_len > max_size) return false;

  memcpy(data, comp.data(), comp_len);
  *out_size = comp_len;
  return true;
}

extern "C" size_t LLVMFuzzerCustomMutator(uint8_t* data, size_t size,
                                          size_t max_size, unsigned int seed) {
  if (size < 4) return LLVMFuzzerMutate(data, size, max_size);

  Rand32 rng = {seed ? seed : 0xA5A5A5A5u};
  uint32_t sig = read_be32(data);

  if (sig == 0x774F4646) {
    if (mutate_woff(data, size, &rng)) return size;
  } else if (sig == 0x774F4632) {
    size_t out_size = size;
    if (mutate_woff2_full(data, size, max_size, &rng, &out_size)) return out_size;
    if (mutate_woff2(data, size, &rng)) return size;
  } else if (sig == 0x00010000 || sig == 0x4F54544F) {
    if (mutate_sfnt(data, size, &rng)) return size;
  }

  return LLVMFuzzerMutate(data, size, max_size);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size == 0) return 0;

  FT_Library lib;
  if (FT_Init_FreeType(&lib)) return 0;

  FT_Long face_index = 0;
  if (size >= 4) {
    uint32_t raw = (data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3];
    face_index = (FT_Long)(raw & 3);
  }

  FT_Face face;
  if (FT_New_Memory_Face(lib, data, (FT_Long)size, face_index, &face)) {
    FT_Done_FreeType(lib);
    return 0;
  }

  FT_Select_Charmap(face, FT_ENCODING_UNICODE);
  const char* fast_env = getenv("FT_FUZZ_FAST");
  int fast_mode = (fast_env && fast_env[0] != '\0');
  const char* mode_env = getenv("FT_FUZZ_MODE");
  int mode_parser = (mode_env && strcmp(mode_env, "parser") == 0);
  int mode_color = (mode_env && strcmp(mode_env, "color") == 0);
  int mode_var = (mode_env && strcmp(mode_env, "var") == 0);

  FT_Set_Pixel_Sizes(face, 0, 16);

  const char* font_format = FT_Get_Font_Format(face);
  if (font_format) {
    if (strcmp(font_format, "Type 1") == 0 || strcmp(font_format, "CID Type 1") == 0) {
      PS_FontInfoRec ps_info;
      PS_PrivateRec ps_private;
      FT_Get_PS_Font_Info(face, &ps_info);
      FT_Get_PS_Font_Private(face, &ps_private);
    }
    if (strcmp(font_format, "CID Type 1") == 0) {
      const char* reg = NULL;
      const char* order = NULL;
      FT_Int supplement = 0;
      FT_Get_CID_Registry_Ordering_Supplement(face, &reg, &order, &supplement);
    }
    if (strcmp(font_format, "BDF") == 0 || strcmp(font_format, "PCF") == 0) {
      BDF_PropertyRec prop;
      FT_Get_BDF_Property(face, "FONT_ASCENT", &prop);
      FT_Get_BDF_Property(face, "PIXEL_SIZE", &prop);
      FT_Get_BDF_Property(face, "WEIGHT_NAME", &prop);
    }
    if (strcmp(font_format, "Windows FNT") == 0) {
      FT_WinFNT_HeaderRec winfnt;
      FT_Get_WinFNT_Header(face, &winfnt);
    }
  }

  if (!mode_parser && FT_HAS_MULTIPLE_MASTERS(face)) {
    FT_MM_Var* mm = NULL;
    if (!FT_Get_MM_Var(face, &mm) && mm && mm->num_axis > 0) {
      FT_UInt axis_count = mm->num_axis;
      if (axis_count > 16) axis_count = 16;
      FT_Fixed* coords = (FT_Fixed*)calloc(axis_count, sizeof(FT_Fixed));
      if (coords) {
        size_t off = 4;
        for (FT_UInt i = 0; i < axis_count; ++i) {
          coords[i] = (FT_Fixed)(fuzz_u32(data, size, &off) & 0xFFFFF);
        }
        FT_Set_Var_Design_Coordinates(face, axis_count, coords);
        free(coords);
      }
      FT_Done_MM_Var(lib, mm);
    }
  }

  FT_Int limit = (face->num_glyphs > 32) ? 32 : face->num_glyphs;
  if (fast_mode && limit > 4) limit = 4;
  FT_Int32 load_flags = FT_LOAD_DEFAULT;
  if (!fast_mode && !mode_parser) load_flags |= FT_LOAD_RENDER | FT_LOAD_COLOR;
  for (FT_Int i = 0; i < limit; ++i) {
    FT_Load_Glyph(face, i, load_flags);
    if (!fast_mode && face->glyph && face->glyph->format == FT_GLYPH_FORMAT_OUTLINE) {
      FT_BBox box;
      FT_Outline_Get_BBox(&face->glyph->outline, &box);
    }
  }

  if (!mode_color) {
    for (FT_ULong cp = 0; cp < 0x200; cp += 7) {
      FT_UInt idx = FT_Get_Char_Index(face, cp);
      if (idx) {
        FT_Load_Glyph(face, idx, load_flags);
        if (!fast_mode && face->glyph && face->glyph->format == FT_GLYPH_FORMAT_OUTLINE) {
          FT_BBox box;
          FT_Outline_Get_BBox(&face->glyph->outline, &box);
        }
      }
    }
  }

  if (!mode_color) {
    size_t off = 8;
    FT_ULong base = (FT_ULong)(fuzz_u32(data, size, &off) & 0xFFFF);
    for (int i = 0; i < 32; ++i) {
      FT_ULong cp = base + (FT_ULong)(i * 13);
      FT_UInt idx = FT_Get_Char_Index(face, cp);
      if (idx) {
        FT_Load_Glyph(face, idx, load_flags);
        if (!fast_mode && face->glyph && face->glyph->format == FT_GLYPH_FORMAT_OUTLINE) {
          FT_BBox box;
          FT_Outline_Get_BBox(&face->glyph->outline, &box);
        }
      }
    }
  }

  if (!fast_mode && !mode_parser) {
    static const FT_Int32 extra_flags[] = {
      FT_LOAD_DEFAULT | FT_LOAD_NO_HINTING,
      FT_LOAD_DEFAULT | FT_LOAD_NO_BITMAP,
      FT_LOAD_TARGET_MONO,
      FT_LOAD_TARGET_LCD
    };
    static const FT_Render_Mode render_modes[] = {
      FT_RENDER_MODE_NORMAL,
      FT_RENDER_MODE_MONO,
      FT_RENDER_MODE_LCD
    };
    FT_Int extra_limit = (face->num_glyphs > 8) ? 8 : face->num_glyphs;
    for (size_t f = 0; f < sizeof(extra_flags) / sizeof(extra_flags[0]); ++f) {
      for (FT_Int i = 0; i < extra_limit; ++i) {
        if (FT_Load_Glyph(face, i, extra_flags[f]) == 0 &&
            face->glyph && face->glyph->format == FT_GLYPH_FORMAT_OUTLINE) {
          for (size_t m = 0; m < sizeof(render_modes) / sizeof(render_modes[0]); ++m) {
            FT_Render_Glyph(face->glyph, render_modes[m]);
          }
        }
      }
    }

    if (face->num_glyphs > 0) {
      FT_Glyph glyph;
      if (FT_Load_Glyph(face, 0, FT_LOAD_DEFAULT) == 0 &&
          FT_Get_Glyph(face->glyph, &glyph) == 0) {
        FT_Glyph_To_Bitmap(&glyph, FT_RENDER_MODE_NORMAL, NULL, 1);
        FT_Done_Glyph(glyph);
      }
    }

    FT_Set_Pixel_Sizes(face, 0, 8);
    if (face->num_glyphs > 0) {
      FT_Load_Glyph(face, 0, FT_LOAD_DEFAULT | FT_LOAD_RENDER);
    }
    FT_Set_Pixel_Sizes(face, 0, 32);
    if (face->num_glyphs > 0) {
      FT_Load_Glyph(face, 0, FT_LOAD_DEFAULT | FT_LOAD_RENDER);
    }
    FT_Set_Pixel_Sizes(face, 0, 16);
  }

  if (!fast_mode && (mode_color || (!mode_parser && FT_HAS_COLOR(face)))) {
    FT_UInt base_glyph = 0;
    FT_UInt layer_glyph = 0;
    FT_UInt layer_color = 0;
    FT_LayerIterator iter;
    iter.p = NULL;
    while (FT_Get_Color_Glyph_Layer(face, base_glyph, &layer_glyph, &layer_color, &iter)) {
      FT_Load_Glyph(face, layer_glyph, load_flags);
      if (++base_glyph > 16) break;
      iter.p = NULL;
    }
  }

  if (mode_parser && FT_IS_SFNT(face)) {
    FT_Bytes base_table = NULL;
    FT_Bytes gdef_table = NULL;
    FT_Bytes gpos_table = NULL;
    FT_Bytes gsub_table = NULL;
    FT_Bytes jstf_table = NULL;
    FT_UInt ot_flags = FT_VALIDATE_BASE | FT_VALIDATE_GDEF |
                       FT_VALIDATE_GPOS | FT_VALIDATE_GSUB |
                       FT_VALIDATE_JSTF;
    if (FT_OpenType_Validate(face, ot_flags, &base_table, &gdef_table,
                             &gpos_table, &gsub_table, &jstf_table) == 0) {
      if (base_table) FT_OpenType_Free(face, base_table);
      if (gdef_table) FT_OpenType_Free(face, gdef_table);
      if (gpos_table) FT_OpenType_Free(face, gpos_table);
      if (gsub_table) FT_OpenType_Free(face, gsub_table);
      if (jstf_table) FT_OpenType_Free(face, jstf_table);
    }

    FT_Bytes gx_tables[FT_VALIDATE_GX_LENGTH];
    memset(gx_tables, 0, sizeof(gx_tables));
    if (FT_TrueTypeGX_Validate(face, FT_VALIDATE_GX | FT_VALIDATE_CKERN,
                               gx_tables, FT_VALIDATE_GX_LENGTH) == 0) {
      for (int i = 0; i < FT_VALIDATE_GX_LENGTH; ++i) {
        if (gx_tables[i]) FT_TrueTypeGX_Free(face, gx_tables[i]);
      }
    }
  }

  if (mode_parser && FT_IS_SFNT(face)) {
    static const FT_Int32 parser_flags[] = {
      FT_LOAD_DEFAULT,
      FT_LOAD_NO_HINTING,
      FT_LOAD_NO_SCALE,
      FT_LOAD_NO_BITMAP
    };
    FT_Int parser_limit = (face->num_glyphs > 16) ? 16 : face->num_glyphs;
    for (size_t f = 0; f < sizeof(parser_flags) / sizeof(parser_flags[0]); ++f) {
      for (FT_Int i = 0; i < parser_limit; ++i) {
        FT_Load_Glyph(face, i, parser_flags[f]);
      }
    }
  }

  if (!fast_mode && FT_IS_SFNT(face)) {
    static const FT_ULong tags[] = {
      FT_MAKE_TAG('B','A','S','E'),
      FT_MAKE_TAG('c','m','a','p'),
      FT_MAKE_TAG('C','B','D','T'),
      FT_MAKE_TAG('C','B','L','C'),
      FT_MAKE_TAG('C','F','F',' '),
      FT_MAKE_TAG('C','F','F','2'),
      FT_MAKE_TAG('n','a','m','e'),
      FT_MAKE_TAG('D','S','I','G'),
      FT_MAKE_TAG('E','B','D','T'),
      FT_MAKE_TAG('E','B','L','C'),
      FT_MAKE_TAG('h','e','a','d'),
      FT_MAKE_TAG('m','a','x','p'),
      FT_MAKE_TAG('f','v','a','r'),
      FT_MAKE_TAG('g','v','a','r'),
      FT_MAKE_TAG('O','S','/','2'),
      FT_MAKE_TAG('h','h','e','a'),
      FT_MAKE_TAG('h','m','t','x'),
      FT_MAKE_TAG('g','l','y','f'),
      FT_MAKE_TAG('G','D','E','F'),
      FT_MAKE_TAG('G','P','O','S'),
      FT_MAKE_TAG('G','S','U','B'),
      FT_MAKE_TAG('H','V','A','R'),
      FT_MAKE_TAG('J','S','T','F'),
      FT_MAKE_TAG('k','e','r','n'),
      FT_MAKE_TAG('l','o','c','a'),
      FT_MAKE_TAG('L','T','S','H'),
      FT_MAKE_TAG('M','V','A','R'),
      FT_MAKE_TAG('m','e','t','a'),
      FT_MAKE_TAG('o','p','b','d'),
      FT_MAKE_TAG('p','r','o','p'),
      FT_MAKE_TAG('t','r','a','k'),
      FT_MAKE_TAG('V','D','M','X'),
      FT_MAKE_TAG('V','O','R','G'),
      FT_MAKE_TAG('V','V','A','R'),
      FT_MAKE_TAG('C','O','L','R'),
      FT_MAKE_TAG('C','P','A','L'),
      FT_MAKE_TAG('S','V','G',' '),
      FT_MAKE_TAG('s','b','i','x'),
      FT_MAKE_TAG('S','T','A','T'),
      FT_MAKE_TAG('a','v','a','r')
    };
    for (size_t i = 0; i < sizeof(tags) / sizeof(tags[0]); ++i) {
      FT_ULong len = 0;
      if (FT_Load_Sfnt_Table(face, tags[i], 0, NULL, &len) == 0 && len > 0) {
        if (len > 1024 * 1024) len = 1024 * 1024;
        FT_Byte* buf = (FT_Byte*)malloc(len);
        if (buf) {
          FT_Load_Sfnt_Table(face, tags[i], 0, buf, &len);
          free(buf);
        }
      }
    }

    FT_UInt name_count = FT_Get_Sfnt_Name_Count(face);
    for (FT_UInt i = 0; i < name_count && i < 16; ++i) {
      FT_SfntName name;
      FT_Get_Sfnt_Name(face, i, &name);
    }
  }

  if (!fast_mode) {
    FT_UInt g0 = 0;
    FT_UInt g1 = 0;
    FT_ULong c0 = FT_Get_First_Char(face, &g0);
    if (g0) {
      FT_ULong c1 = FT_Get_Next_Char(face, c0, &g1);
      (void)c1;
      if (g1) {
        FT_Vector kern;
        FT_Get_Kerning(face, g0, g1, FT_KERNING_DEFAULT, &kern);
      }
    }
  }

  if (!fast_mode) {
    FT_Select_Charmap(face, FT_ENCODING_MS_SYMBOL);
    FT_Select_Charmap(face, FT_ENCODING_ADOBE_STANDARD);
    FT_Select_Charmap(face, FT_ENCODING_UNICODE);
  }

  FT_Done_Face(face);
  FT_Done_FreeType(lib);
  return 0;
}
```

구체적으로는 다음과 같은 방향을 반영하였습니다.

- 다양한 포맷 처리 흐름(TTF/OTF/WOFF/WOFF2/Type1/BDF/PCF)을 최대한 타도록 구성합니다.
- `FT_Load_Glyph`, `FT_Render_Glyph`, `FT_Glyph_To_Bitmap` 등을 통해 glyph 로딩 및 렌더링 경로를 활성화합니다.
- Variations 폰트의 경우 `FT_Get_MM_Var`, `FT_Set_Var_Design_Coordinates` 등을 통해 좌표 적용 경로가 실행되도록 유도합니다.
- 컬러 폰트는 레이어 처리 API를 통해 `COLR/CPAL/SVG/sbix` 계열 처리 흐름이 타도록 유도합니다.
- OpenType 및 GX 관련 검증 루틴을 실행하여 테이블 검증·파싱 경로 또한 커버하도록 구성합니다.
- SFNT 테이블 직접 로딩 및 name 테이블 접근 등을 통해 테이블 파싱 분기 커버리지를 확장합니다.

---

### 4. Corpus 구성 전략

퍼징 커버리지를 확장하는 데 있어 Corpus 구성은 매우 중요한 요소입니다. 저는 초기부터 높은 커버리지를 확보하기 위해, 공격 표면에 해당하는 다양한 폰트 파일들을 외부에서 다운로드하여 Seed Corpus를 구성하였습니다.

```bash
#!/usr/bin/env bash
set -euo pipefail

CORPUS_ROOT="/home/hiariz/fuzzing/corpus"
mkdir -p \
  "$CORPUS_ROOT/ttf" \
  "$CORPUS_ROOT/otf" \
  "$CORPUS_ROOT/variable" \
  "$CORPUS_ROOT/color" \
  "$CORPUS_ROOT/woff2" \
  "$CORPUS_ROOT/woff" \
  "$CORPUS_ROOT/type1" \
  "$CORPUS_ROOT/bdf" \
  "$CORPUS_ROOT/pcf" \
  "$CORPUS_ROOT/extras/stream" \
  "$CORPUS_ROOT/extras/compress" \
  "$CORPUS_ROOT/extras/pfr" \
  "$CORPUS_ROOT/extras/type42" \
  "$CORPUS_ROOT/extras/svg" \
  "$CORPUS_ROOT/extras/cache" \
  "$CORPUS_ROOT/extras/incremental" \
  "$CORPUS_ROOT/extras/bdf_pcf" \
  "$CORPUS_ROOT/extras/validate" \
  "$CORPUS_ROOT/color_svg" \
  "$CORPUS_ROOT/color_sbix" \
  "$CORPUS_ROOT/color_colr"

fetch() {
  local url="$1"
  local out="$2"
  if [ ! -s "$out" ]; then
    if ! curl -L --fail "$url" -o "$out"; then
      echo "warn: failed to fetch $url" >&2
      rm -f "$out"
    fi
  fi
}

fetch_any() {
  local out="$1"
  shift
  for url in "$@"; do
    if curl -L --fail "$url" -o "$out"; then
      return 0
    fi
    rm -f "$out"
  done
  echo "warn: failed to fetch $(printf '%s ' "$@")" >&2
  return 1
}

copy_some() {
  local dest="$1"
  local limit="$2"
  shift 2
  local count=0
  for f in "$@"; do
    [ -f "$f" ] || continue
    cp -n "$f" "$dest"/
    count=$((count + 1))
    if [ "$count" -ge "$limit" ]; then
      break
    fi
  done
}

copy_from_find() {
  local dest="$1"
  local limit="$2"
  local root="$3"
  local pattern="$4"
  local count=0
  find "$root" -type f -name "$pattern" 2>/dev/null | while read -r f; do
    cp -n "$f" "$dest"/
    count=$((count + 1))
    if [ "$count" -ge "$limit" ]; then
      break
    fi
  done
}

make_compressed() {
  local dest="$1"
  shift
  if command -v gzip >/dev/null 2>&1; then
    for f in "$@"; do
      [ -f "$f" ] || continue
      gzip -c "$f" >"$dest/$(basename "$f").gz"
    done
  fi
  if command -v bzip2 >/dev/null 2>&1; then
    for f in "$@"; do
      [ -f "$f" ] || continue
      bzip2 -c "$f" >"$dest/$(basename "$f").bz2"
    done
  fi
}

# TTF basics
fetch "https://raw.githubusercontent.com/googlefonts/noto-fonts/main/hinted/ttf/NotoSans/NotoSans-Regular.ttf" \
  "$CORPUS_ROOT/ttf/NotoSans-Regular.ttf"
fetch "https://raw.githubusercontent.com/googlefonts/noto-fonts/main/hinted/ttf/NotoSerif/NotoSerif-Regular.ttf" \
  "$CORPUS_ROOT/ttf/NotoSerif-Regular.ttf"
fetch "https://raw.githubusercontent.com/googlefonts/opensans/main/fonts/ttf/OpenSans-Regular.ttf" \
  "$CORPUS_ROOT/ttf/OpenSans-Regular.ttf"
fetch "https://raw.githubusercontent.com/googlefonts/opensans/main/fonts/ttf/OpenSans-Bold.ttf" \
  "$CORPUS_ROOT/ttf/OpenSans-Bold.ttf"
fetch "https://raw.githubusercontent.com/googlefonts/opensans/main/fonts/ttf/OpenSans-Italic.ttf" \
  "$CORPUS_ROOT/ttf/OpenSans-Italic.ttf"

# OTF CFF
fetch "https://github.com/adobe-fonts/source-serif/raw/release/OTF/SourceSerif4-Regular.otf" \
  "$CORPUS_ROOT/otf/SourceSerif4-Regular.otf"
fetch "https://github.com/adobe-fonts/source-sans/raw/release/OTF/SourceSans3-Regular.otf" \
  "$CORPUS_ROOT/otf/SourceSans3-Regular.otf"

# Variable fonts
fetch "https://raw.githubusercontent.com/googlefonts/roboto-flex/main/fonts/RobotoFlex%5BGRAD%2CXOPQ%2CXTRA%2CYOPQ%2CYTAS%2CYTDE%2CYTFI%2CYTLC%2CYTUC%2Copsz%2Cslnt%2Cwdth%2Cwght%5D.ttf" \
  "$CORPUS_ROOT/variable/RobotoFlex-VariableFont.ttf"
fetch "https://raw.githubusercontent.com/rsms/inter/master/docs/font-files/InterVariable.ttf" \
  "$CORPUS_ROOT/variable/InterVariable.ttf"
fetch "https://raw.githubusercontent.com/googlefonts/opensans/main/fonts/variable/OpenSans%5Bwdth%2Cwght%5D.ttf" \
  "$CORPUS_ROOT/variable/OpenSans-VariableFont.ttf"

# Color fonts
fetch "https://github.com/googlefonts/noto-emoji/raw/main/fonts/NotoColorEmoji.ttf" \
  "$CORPUS_ROOT/color/NotoColorEmoji.ttf"

# WOFF2
fetch "https://raw.githubusercontent.com/rsms/inter/master/docs/font-files/InterVariable.woff2" \
  "$CORPUS_ROOT/woff2/InterVariable.woff2"
# WOFF
fetch_any "$CORPUS_ROOT/woff/InterVariable.woff" \
  "https://raw.githubusercontent.com/FontFaceKit/open-sans/gh-pages/fonts/Regular/OpenSans-Regular.woff" \
  "https://raw.githubusercontent.com/FontFaceKit/open-sans/master/fonts/Regular/OpenSans-Regular.woff"

# Type1 (.t1)
fetch "https://raw.githubusercontent.com/ArtifexSoftware/urw-base35-fonts/master/fonts/NimbusRoman-Regular.t1" \
  "$CORPUS_ROOT/type1/NimbusRoman-Regular.t1"
fetch "https://raw.githubusercontent.com/ArtifexSoftware/urw-base35-fonts/master/fonts/NimbusSans-Regular.t1" \
  "$CORPUS_ROOT/type1/NimbusSans-Regular.t1"

# Bitmap fonts (BDF/PCF)
fetch "https://gitlab.freedesktop.org/xorg/font/misc-misc/-/raw/master/6x13.bdf" \
  "$CORPUS_ROOT/bdf/6x13.bdf"
fetch "https://raw.githubusercontent.com/rsms/inter/master/docs/font-files/InterVariable-Italic.woff2" \
  "$CORPUS_ROOT/woff2/InterVariable-Italic.woff2"

# Color fonts (COLR/CPAL, SVG, sbix)
fetch "https://raw.githubusercontent.com/googlefonts/color-fonts/main/fonts/twemoji_smiley-glyf_colr_1.ttf" \
  "$CORPUS_ROOT/color_colr/twemoji_smiley-glyf_colr_1.ttf"
fetch "https://raw.githubusercontent.com/googlefonts/color-fonts/main/fonts/test_glyphs-glyf_colr_1_variable.ttf" \
  "$CORPUS_ROOT/color_colr/test_glyphs-glyf_colr_1_variable.ttf"
fetch "https://raw.githubusercontent.com/googlefonts/color-fonts/main/fonts/twemoji_smiley-cff_colr_1.otf" \
  "$CORPUS_ROOT/color_colr/twemoji_smiley-cff_colr_1.otf"
fetch "https://raw.githubusercontent.com/googlefonts/color-fonts/main/fonts/twemoji_smiley-cff2_colr_1.otf" \
  "$CORPUS_ROOT/color_colr/twemoji_smiley-cff2_colr_1.otf"
fetch "https://raw.githubusercontent.com/googlefonts/color-fonts/main/fonts/twemoji_smiley-picosvg.ttf" \
  "$CORPUS_ROOT/color_svg/twemoji_smiley-picosvg.ttf"
fetch "https://raw.githubusercontent.com/googlefonts/color-fonts/main/fonts/twemoji_smiley-untouchedsvgz.ttf" \
  "$CORPUS_ROOT/color_svg/twemoji_smiley-untouchedsvgz.ttf"
fetch "https://raw.githubusercontent.com/googlefonts/color-fonts/main/fonts/twemoji_smiley-sbix.ttf" \
  "$CORPUS_ROOT/color_sbix/twemoji_smiley-sbix.ttf"

shopt -s nullglob

# Extras: stream/cache/incremental/validate
copy_some "$CORPUS_ROOT/extras/stream" 20 \
  "$CORPUS_ROOT/ttf"/*.ttf "$CORPUS_ROOT/otf"/*.otf \
  "$CORPUS_ROOT/woff2"/*.woff2 "$CORPUS_ROOT/woff"/*.woff
copy_some "$CORPUS_ROOT/extras/cache" 20 \
  "$CORPUS_ROOT/ttf"/*.ttf "$CORPUS_ROOT/otf"/*.otf
copy_some "$CORPUS_ROOT/extras/incremental" 20 \
  "$CORPUS_ROOT/ttf"/*.ttf "$CORPUS_ROOT/otf"/*.otf
copy_some "$CORPUS_ROOT/extras/validate" 20 \
  "$CORPUS_ROOT/ttf"/*.ttf "$CORPUS_ROOT/otf"/*.otf

# Extras: svg
copy_some "$CORPUS_ROOT/extras/svg" 20 "$CORPUS_ROOT/color_svg"/*.ttf

# Extras: bdf/pcf
copy_some "$CORPUS_ROOT/extras/bdf_pcf" 20 "$CORPUS_ROOT/bdf"/*.bdf "$CORPUS_ROOT/pcf"/*.pcf

# Extras: compress (gzip/bzip2)
make_compressed "$CORPUS_ROOT/extras/compress" \
  "$CORPUS_ROOT/ttf"/*.ttf "$CORPUS_ROOT/otf"/*.otf \
  "$CORPUS_ROOT/bdf"/*.bdf "$CORPUS_ROOT/pcf"/*.pcf

# Extras: PFR/Type42 (best-effort from local tree)
copy_from_find "$CORPUS_ROOT/extras/pfr" 20 "/home/hiariz/fuzzing/freetype" "*.pfr"
copy_from_find "$CORPUS_ROOT/extras/type42" 20 "/home/hiariz/fuzzing/freetype" "*.t42"
copy_from_find "$CORPUS_ROOT/extras/type42" 20 "/home/hiariz/fuzzing/freetype" "*.type42"

shopt -u nullglob

printf "\nSeed corpus created under %s\n" "$CORPUS_ROOT"
```

이렇게 구성된 하네스와 코퍼스를 토대로 다음과 같이 명령어를 실행하여 퍼징을 진행하였습니다.

```bash
/home/hiariz/fuzzing/ft_fuzzer -max_len=1048576 /home/hiariz/fuzzing/corpus
```

이 과정에서 `-max_len` 옵션 외에도 `-use_value_profile` 등의 옵션을 추가로 적용해보면서, 가능한 한 더 많은 코드 경로가 실행되도록 커버리지를 확장하는 방향으로 테스트를 진행하였습니다.

---

### 5. Timeout 크래시 분석 (GDB 기반 원인 분석)

그 결과, 퍼징 도중 timeout 로그가 출력되면서 특정 입력 파일이 크래시(정확히는 timeout artifact)로 저장되는 현상을 확인할 수 있었습니다.

일반적인 메모리 크래시(SIGSEGV 등)와 달리, 프로세스가 특정 구간에서 과도하게 오래 실행되면서 응답하지 않는 형태였기 때문에, 단순한 크래시가 아니라 DoS 가능성을 의심하고 분석을 진행하였습니다.

#### 5.1. GDB로 확인한 실행 지점

생성된 timeout 입력을 대상으로 GDB를 붙여 실행 흐름을 추적해보았습니다. 분석 결과, 렌더링 단계에서 `ftgrays.c` 모듈의 특정 함수 내부에서 실행이 장시간 지연되고 있음을 확인하였습니다.

특히 그레이스케일 래스터라이저 경로에서 호출되는 `gray_render_line` 함수가 지연의 중심이었습니다. 해당 함수는 라인(line)을 렌더링하는 과정에서 픽셀 단위로 한 칸씩 이동하며 반복 수행하는 구조를 가지고 있어, 입력 좌표가 비정상적으로 커질 경우 반복 횟수가 폭증할 수 있는 형태였습니다.

#### 5.2. Root Cause: 과도한 루프 반복과 클리핑/검증 부족

##### (1) gray_render_line의 픽셀 단위 반복 구조
`gray_render_line`은 선을 그릴 때 시작점에서 끝점까지 x 좌표를 1씩 증가시키는 방식으로 반복을 수행합니다. 즉, "선 하나"를 그리더라도 내부적으로는 "픽셀 단위"로 계산이 누적되는 구조입니다.

##### (2) 수평 클리핑 및 sanity check 부재
문제가 되었던 입력에서는 선의 목표 좌표(`to_x`)가 비정상적으로 큰 값으로 설정되어 있었습니다. 이 경우, 해당 선이 실제로는 화면 영역(혹은 렌더링 대상 영역) 밖에 존재하더라도, 함수 내부에서 이를 조기에 배제하지 못하고 끝까지 모든 픽셀을 계산하려고 시도하게 됩니다.

즉, 수평 방향 클리핑(horizontal clipping) 또는 "좌표가 비정상적으로 큰 경우 early exit" 같은 sanity check가 부족한 상태로 보였습니다.

##### (3) 알고리즘 복잡도 증가 (최악의 경우 O(N²) 양상)
또한 반복 루프 내부에서는 `gray_set_cell`과 같은 함수 호출이 연쇄적으로 발생하는데, 이 과정에서 내부 데이터 구조 처리 방식에 따라 선형 탐색이 반복되는 형태가 관찰되었습니다.

결과적으로 입력 좌표가 커질수록,

- `gray_render_line` 자체의 반복 횟수 증가(수백만 회 단위)
- 루프 내부 연산까지 누적

이 결합되면서 최악의 경우 사실상 O(N²)에 가까운 성능 저하가 발생할 수 있고, 이는 CPU 자원 고갈을 통해 DoS를 유발할 수 있다고 판단하였습니다.

GDB 스냅샷에서도 현재 위치(`ex1`) 대비 목표 좌표(`to_x`)가 매우 큰 값으로 설정되어 있어, 남은 반복 횟수가 과도하게 큰 상태임을 확인할 수 있었습니다.

---

### 6. 성능 비교 실험 (Proof of Concept)

이 문제가 실제로 얼마나 심각한지 확인하기 위해, 정상 폰트 파일과 퍼징으로 발견된 timeout 입력 파일을 대상으로 렌더링 시간을 비교 측정해보았습니다.

정상 입력은 약 5~7ms 내외로 빠르게 종료되는 반면, 크래시 파일은 776.78초 (약 12분 56초) 이상 실행이 지속되어 수동으로 중단해야 했습니다.

즉, 정상 대비 수십만 배 수준의 성능 저하가 발생한 것이며, 실제 서비스 환경(브라우저/서버/모바일 등)에서 해당 입력이 처리될 경우 심각한 서비스 거부 상황을 유발할 수 있습니다.

---

### 7. 벤더 제보, 패치 및 CVE 발급 진행 상황

앞서 분석한 내용을 토대로, 해당 취약점에 대해 FreeType 개발사에 공식적으로 제보를 진행하였습니다. 제보 과정에서는 퍼징 환경, 재현 가능한 입력 파일, GDB 분석 결과, 그리고 성능 저하(DoS) 발생 원인을 함께 전달하였습니다.

그 결과, 개발사 측에서도 해당 이슈를 Denial of Service 취약점으로 인정하였으며, 내부 검토 이후 패치가 실제로 진행되었습니다.
- [https://gitlab.freedesktop.org/freetype/freetype/-/issues/1381](https://gitlab.freedesktop.org/freetype/freetype/-/issues/1381)

현재 해당 취약점에 대해서는 CVE 번호 발급을 신청한 상태이며, 대기 중에 있습니다.

---

### 8. FreeType 퍼징 후기

이번에 처음으로 LibFuzzer라는 퍼저를 실제 퍼징에 활용해보았는데, 기존에 사용해왔던 AFL++ 계열 퍼저들과 비교했을 때 빌드 과정이 비교적 간단하고, 초기 설정 이후 곧바로 퍼징을 수행할 수 있다는 점이 매우 편리하게 느껴졌습니다. 특히 타겟이 라이브러리 형태일 경우, LibFuzzer의 장점이 더욱 잘 드러난다고 생각합니다.

퍼징을 진행하면서 다시 한 번 느낀 점은, 단순히 퍼저를 실행하는 것보다 타겟의 Attack Surface를 명확히 파악하는 과정이 훨씬 중요하다는 점이었습니다. 어떤 코드 경로가 실제로 외부 입력에 의해 도달 가능한지 분석하고, 이를 기준으로 효과적인 입력 파일(Corpus)을 구성하고 하네스를 설계하는 작업이 퍼징의 성과를 크게 좌우한다는 것을 체감할 수 있었습니다.

또한 FreeType과 같이 규모가 크고 전 세계적으로 널리 사용되는 오픈소스 라이브러리를 대상으로, 실제 보안 취약점을 발견하고 이를 개발사에 제보하여 패치까지 이어졌다는 점은 개인적으로도 매우 값진 경험이었습니다. 단순한 실습을 넘어, 오픈소스 보안 생태계에 직접 기여할 수 있었다는 점에서 큰 보람을 느꼈습니다.

이번 분석 과정에서 특히 인상 깊었던 부분은, 소스코드 분석과 디버깅 과정에서 LLM을 적극적으로 활용함으로써 분석 시간을 효과적으로 줄일 수 있었다는 점입니다. 앞으로 퍼징과 취약점 분석 분야에서도 LLM이 더욱 정교하게 활용된다면, 보다 효율적으로 복잡한 코드 베이스를 이해하고 취약점을 발견할 수 있지 않을까 하는 가능성도 함께 느낄 수 있었습니다.

---

## Part 2. HarfBuzz Null Pointer Dereference 취약점 발견 및 분석

### Target

개인적으로 퍼징을 진행할 때는 타겟이 어떤 기능이 있고 어떤 역할을 수행하는지에 대해 아는 것이 중요하다고 생각합니다.
Harfbuzz는 어떤 역할을 하고 어떤 기능이 있는지 Docs를 통해 먼저 확인을 진행했습니다. 

### Harfbuzz?

이곳에서 HarfBuzz의 기능과 역할을 확인할 수 있습니다.
- [https://harfbuzz.github.io](https://harfbuzz.github.io)

> HarfBuzz는 텍스트 형태 변환 엔진으로, 폰트와 유니코드를 입력받아 해당 폰트에 대응하는 글리프(Glyph)를 선택하고 배치하며, 모든 레이아웃 규칙과 폰트 기능을 적용합니다. 그 후 해당 언어와 문자 체계에 맞춰 배열된 문자열을 반환하는 프로그램입니다.

→ 한마디로 HarfBuzz는 폰트와 유니코드를 입력받아 문자에 맞는 실제 모양(글리프)을 선택하고 화면에 배치할 위치를 결정하는 엔진입니다.

---

### 1. Build

문서에 필요한 의존성이 명시되어 있어 해당 내용을 따라 진행했습니다.
- [https://harfbuzz.github.io/building.html#building.linux](https://harfbuzz.github.io/building.html#building.linux)

```bash
sudo apt install  gcc g++ libfreetype6-dev libglib2.0-dev libcairo2-dev
sudo apt-get install  meson pkg-config gtk-doc-tools
```

일반적인 퍼징 프로젝트는 먼저 일반 빌드를 진행한 후 sanitizer를 추가하여 빌드합니다. 하지만 빌드를 여러 번 진행하는 것을 피하기 위해 바로 sanitizer 빌드를 진행했습니다.

```bash
git clone https://github.com/harfbuzz/harfbuzz.git
cd harfbuzz

meson setup build \
  --prefix= <prefix> \
  --default-library=static \
  -Db_sanitize=address,undefined \
  -Dbuildtype=debug

meson compile -C build -j $(nproc) && meson install -C build
```

빌드 명령어 설명:

- `--prefix`: 컴파일된 결과물이 설치될 경로
- `--default-library=static`: 정적 라이브러리로 빌드
    - LibFuzzer와 하네스를 컴파일할 때 HarfBuzz 라이브러리를 하나로 통합해야 하기 때문에 정적 빌드로 진행
- `-Db_sanitize=address,undefined`: Sanitizer 옵션
    - ASAN: 메모리 손상을 감지
    - UBSAN: 정수 오버플로우나 유효하지 않은 포인터 연산 등을 감지
- `-Dbuildtype=debug`: 디버깅 심볼을 포함해서 빌드
    - 분석할 때 용이하기 때문

prefix로 설정한 위치의 심볼을 확인한 결과 ASAN이 정상적으로 적용된 것을 확인했습니다.

---

### 2. Binary

빌드 완료 후 4개의 바이너리가 생성됩니다. 

#### hb-info

기능: 폰트 파일의 내부 메타데이터 및 지원하는 기능을 조회

#### hb-shape

기능: 유니코드가 어떤 글리프 ID로 변환되었는지 각 글리프의 정확한 좌표와 간격 정보가 터미널에 수치로 표시

#### hb-view

기능: 셰이핑된 결과를 시각적으로 렌더링하여 이미지 파일(PNG, SVG, PDF 등)로 출력

#### hb-subset

기능: 원본 폰트 파일에서 필요한 글리프만 추출하여 새로운 최적화된 폰트 파일을 생성

더 자세한 사용 방법은 다음 링크를 참고하시기 바랍니다. 
- [https://harfbuzz.github.io/utilities.html#utilities-command-line-tools](https://harfbuzz.github.io/utilities.html#utilities-command-line-tools)

---

### 3. Strategy

#### Fuzzer

HarfBuzz의 취약점 탐색을 위해 LibFuzzer로 선택했습니다. 선정 사유는 다음과 같습니다.

- In-Process 퍼징: 새로운 프로세스를 생성하는 `fork()` 오버헤드 없이 동일 프로세스 내에서 타겟 API를 반복 호출하므로 실행 속도가 빠릅니다.
- API 중심 테스트: HarfBuzz는 방대한 라이브러리 API로 구성되어 있어 특정 함수(`hb_shape`)를 직접 타겟팅하는 LibFuzzer의 하네스(Harness) 구조가 가장 적합합니다.
- 효율적 커버리지 탐색: LLVM 컴파일러 인프라를 활용한 커버리지 가이드 방식을 통해 복잡한 폰트 파싱 로직의 깊은 곳까지 탐색 가능합니다.

#### Corpus

HarfBuzz는 폰트와 유니코드를 입력으로 받습니다. 하지만 LibFuzzer는 입력값을 하나만 받을 수 있습니다. 폰트와 유니코드를 모두 사용한다면 더 높은 커버리지를 얻을 수 있을 것이라고 생각하여 두 가지를 모두 활용하고 싶었습니다.

하지만 LibFuzzer는 입력을 하나만 받을 수 있기 때문에 두 가지를 동시에 사용할 수 없습니다. 따라서 다음과 같은 3가지 전략을 고려했습니다.

1. 퍼저를 개량해서 Input을 2개 받을 수 있도록 한다.
2. 유니코드를 무작위로 생성하는 코드를 만들고 Font를 Corpus로 사용한다.
3. Font만 사용한다.

최종적으로는 3번 전략을 선택했습니다. 그 이유는 다음과 같습니다.

- 1번의 경우 퍼저를 개량할 수는 있지만, 그 과정에서 오버헤드가 커질 것으로 판단하여 제외했습니다.
- 2번의 경우 유니코드를 무작위로 생성하여 파일로 저장하고 폰트와 함께 사용하려고 했지만 버그 발생 시 재현이 어렵고 오버헤드가 발생할 것으로 판단했습니다. 또한 유니코드 관련 버그는 대부분 해결되었을 것으로 예상했습니다.

결국 폰트만 사용하는 전략을 선택했습니다.

폰트는 GitHub Public 저장소를 크롤링하는 코드를 작성해 ttf, ttc, otf, otc 확장자 폰트 파일을 수집했습니다. GitHub 저장소를 사용한 이유는 일반적으로 공개된 폰트를 사용할 경우 저작권 문제가 발생할 수 있기 때문에 자유롭게 사용 가능한 Public 저장소를 활용했습니다.

---

### 4. Harness

본격적인 퍼징에 앞서 코드 오디팅을 진행했습니다. 코드 오디팅을 통해 코드의 이해도를 높이고 취약점이 존재할 수 있는 부분을 파악할 수 있기 때문입니다.

코드 오디팅은 3개의 바이너리(`hb-subset`, `hb-shape`, `hb-view`)를 중심으로 진행했습니다. 분석 내용이 길어서 3개를 모두 설명하기는 어렵지만 `hb-subset`을 예시로 설명하겠습니다.

`main(util/hb-subset.cc)`

```cpp
int
main (int argc, char **argv)
{
  return batch_main<subset_main_t, true> (argc, argv);
}
```

먼저 `hb-subset`의 `main` 함수에서 어떤 함수를 호출하는지 확인했습니다.

`batch_main` 함수를 호출하는 것을 확인했습니다. IDE의 함수 따라가기 기능을 사용하여 해당 함수를 파악했습니다.

`batch_main(util/batch.h)`

```cpp
batch_main (int argc, char **argv)
{
  if (argc == 2 && !strcmp (argv[1], "--batch"))
  {
    int ret = 0;
    char buf[4092];
    while (fgets (buf, sizeof (buf), stdin))
    {
      size_t l = strlen (buf);
      if (l && buf[l - 1] == '\n') buf[l - 1] = '\0';

      char *args[64];
      argc = 0;
      args[argc++] = argv[0];
      char *p = buf, *e;
      args[argc++] = p;
      while ((e = strchr (p, ';')) && argc < (int) ARRAY_LENGTH (args))
      {
	*e++ = '\0';
	while (*e == ';')
	  e++;
	args[argc++] = p = e;
      }

      int result = main_t () (argc, args);

      if (report_status)
	fprintf (stdout, result == 0 ? "success\n" : "failure\n");
      fflush (stdout);

      ret = MAX (ret, result);
    }
    return ret;
  }

  int ret = main_t () (argc, argv);
  if (report_status && ret != 0)
    fprintf (stdout, "error: Operation failed. Probably a bug. File github issue.\n");
  return ret;
}
```

위에서 찾은 `batch_main` 함수입니다. 코드 오디팅에서 중요한 것은 하네스를 작성할 때 필요한 부분을 판별하는 능력입니다. 코드 분석 시 특히 주의 깊게 봐야 하는 부분은 프로그램의 초기 설정을 수행하는 initialize 부분과 객체나 동적 메모리를 할당하고 해제하는 부분입니다. 대부분의 하네스에서 발생하는 오류는 동적으로 할당한 메모리를 해제하지 않거나 잘못 해제하여 발생하는 경우가 많기 때문입니다.

`if`문을 보면 매개변수 확인과 `--batch` 옵션 처리 부분을 확인할 수 있지만, 이 부분은 중요하지 않습니다. 핵심은 `int result = main_t () (argc, args);` 부분이므로 이 부분을 집중적으로 분석해야 합니다.

`subset_main_t(util/hb-subset.cc)`

```cpp
struct subset_main_t : option_parser_t, face_options_t, output_options_t<false>
{
  subset_main_t ()
  : input (hb_subset_input_create_or_fail ())
  {}
  ~subset_main_t ()
  {
    hb_subset_input_destroy (input);
  }
```

코드 해석 능력이 부족한 경우가 있습니다. 저의 경우 C++ 해석 능력이 부족하여 함수가 어디로 이동하는지 파악하기 어려울 때가 있는데 이럴 때는 pwndbg와 같은 동적 분석 도구를 사용하여 함수의 흐름을 파악합니다.

또는 전혀 감을 잡지 못하는 경우 AI를 활용하여 코드를 분석하기도 합니다. 최근 AI 기술이 발전하여 이 방법을 적극 활용하고 있습니다.

#### Flow

3개의 바이너리를 분석한 후 어떤 하네스를 작성할지 고민했습니다. 분석 결과 이 3가지를 유기적으로 연결할 수 있을 것 같다는 생각이 들었습니다. 이때까지만 해도 corpus를 2개 사용해도 될 것 같다고 생각하여 다음과 같은 흐름을 고려했습니다.

하네스 흐름:

1. 무작위로 유니코드 생성하는 코드
2. subset 진행해서 폰트를 유니코드 최적화 진행
3. shape를 사용해서 텍스트 수치 확인
4. view로 터미널 혹은 파일로 저장
5. 1~4를 반복

장점:

- 단일 기능만 테스트했을 때보다 버그를 찾기 쉬울 것 같음
- 커버리지는 상대적으로 높음

단점:

- 실행 시간 매우 오래 걸릴 것 같음
- 버그를 발견했을 때 분석이 어려울 것 같음(유니코드)
- 개인적으로 커버리지가 높다고 해서 버그를 잘 찾는 것은 아니라고 생각함
    - 이 경우는 커버리지가 깊지 않기 때문에 오히려 더 어려울 것으로 판단
    

결론적으로 이 하네스는 폐기하기로 결정하고 타협하여 subset → shape를 수행하는 하네스를 작성했습니다. HarfBuzz는 OSS-Fuzz에서도 퍼징이 진행되고 있어 이와 차별화된 코드를 작성했습니다. 차별점은 다음과 같습니다.

| 항목 | OSS-Fuzz | 필자 |
| --- | --- | --- |
| 구조 | 분리형 (subset/shape) | 파이프라인형 (subset→shape) |
| 입력 | 고정/단순 파싱 | 구조화된 파싱 (10+ 바이트 헤더) |
| 기능 | 기본 기능만 | 8가지 flags × 8가지 features |

표에서 알 수 있듯이 OSS-Fuzz는 단일 기능을 단순하게 테스트하는 반면 필자의 하네스는 subset과 shape를 연결하여 기능을 확장했습니다.

---

### 5. Start Fuzzing~

하네스를 작성한 후에는 컴파일을 진행했습니다. 

> https://github.com/harfbuzz/harfbuzz/blob/main/test/fuzzing/meson.build

해당 위치에 하네스를 컴파일할 수 있는 `meson.build` 파일이 있어 이 파일을 수정해 진행했습니다.

```bash
tests = [
  'hb-shape-fuzzer.cc',
  'hb-subset-fuzzer.cc',
  'hb-set-fuzzer.cc',
  'hb-draw-fuzzer.cc',
  'hb-repacker-fuzzer.cc',
  'harness.cc',
]

# Build the binaries
foreach file_name : tests
  test_name = file_name.split('.')[0]

  sources = [file_name]
  fuzzer_ldflags = []
  extra_cpp_args = []

  if get_option('fuzzer_ldflags') == ''
    sources += 'main.cc'
  else
    fuzzer_ldflags += get_option('fuzzer_ldflags').split()
    extra_cpp_args += '-DHB_IS_IN_FUZZER'
  endif

...
```

`harness.cc`를 추가한 후 다음과 같은 명령어로 컴파일을 진행했습니다.

```bash
cd /home/wjddn0623/Knights_Frontier/fuzzing/harfbuzz/test/fuzzing

CXX=clang++ \
CXXFLAGS="-fsanitize=address,fuzzer-no-link" \
meson setup fuzzbuild \
  --default-library=static \
  -Dfuzzer_ldflags="-fsanitize=address,fuzzer" \
  -Db_sanitize=address,undefined \
  -Dexperimental_api=true

ninja -Cfuzzbuild harness
```

이후 4가지 타입의 폰트를 적절히 섞어 하나의 디렉토리에 모은 후 퍼징을 진행했습니다.

```bash
ASAN_OPTIONS=detect_leaks=0 \
./harness \
  -fork=8 \
  -ignore_timeouts=1 \
  -ignore_crashes=0 \
  -timeout=30 \
  -max_len=1048576 \
  -len_control=100 \
  -artifact_prefix=crashes/ \
  -print_final_stats=1 \
  corpus
```

- `ASAN_OPTIONS=detect_leaks=0`: 메모리 누수 감지를 비활성화
    - FreeType에서 누수가 감지되는 경우가 있어 이를 무시하고 진행
- `-fork=8`: 8개의 프로세스를 띄워서 퍼징을 진행
- `-ignore_timeouts=1`: 타임아웃이 발생해도 퍼징 종료되지 않음
- `-ignore_crashes=0`: 크래시가 발생한 경우 중지
- `-timeout=30`: 입력 시간을 30초로 제한
- `-max_len=1048576`: 입력 데이터의 최대 크기를 1MB로 제한
- `-len_control=100`: 작은 입력값부터 시도하다가 점진적으로 크기를 늘려가서 진행
- `-artifact_prefix=crashes/`: 크래시를 유발한 파일을 저장할 디렉토리 선언
- `-print_final_stats`: 퍼징 종료 후 통계를 요약해서 보여줌

이 명령어로 퍼징을 진행한 결과 짧은 시간 내에 크래시가 발생했습니다.

---

### 6. Root Cause

크래시가 발생했고 이것이 하네스의 문제인지 실제 타겟의 크래시인지 확인하기 위해 먼저 스택 로그를 확인했습니다. 확인 결과 크래시는 타겟 소스코드 내에서 발생한 것으로 확인되어 본격적인 분석을 시작했습니다.

로그를 확인한 결과 널 포인터 역참조(Null Pointer Dereference)임을 확인했습니다. 스택 로그의 최상단부터 확인하면서 동적 분석을 진행했습니다. 천천히 분석하여 어떤 부분이 NULL이 되는지 확인했습니다.

원인은 다음과 같습니다.

```cpp
// src/hb-ot-cmap-table.hh:1669-1675
static SubtableUnicodesCache* create (hb_blob_ptr_t<cmap> source_table)
{
  SubtableUnicodesCache* cache =
      (SubtableUnicodesCache*) hb_malloc (sizeof(SubtableUnicodesCache));
  new (cache) SubtableUnicodesCache (source_table);
  return cache;
}
```

해당 로직의 핵심적인 보안 결함은 메모리 할당 성공 여부에 대한 검증 부재에 있습니다.

1. 할당 실패 가능성: `hb_malloc`은 시스템 메모리가 부족하거나 과도한 요청이 있을 경우 `NULL`을 반환할 수 있습니다.
2. 널 포인터 역참조: 코드에서는 `hb_malloc`의 반환값인 `cache` 변수가 `NULL`인지 확인하는 방어 로직이 존재하지 않습니다.
3. Placement New의 위험성: `new (cache) SubtableUnicodesCache (source_table)` 구문은 `cache`가 가리키는 주소에 생성자를 실행합니다. 만약 `cache`가 `NULL`일 경우, 유효하지 않은 메모리 주소(0x0)에 객체 데이터를 쓰려고 시도하게 되어 널 포인터 역참조로 인한 프로세스 비정상 종료가 발생합니다.

---

### 7. Report

GitHub에서 취약점을 제보하는 방법은 Security로 작성하거나 메일로 제보하는 방법이 있으며 전자를 사용하여 리포트를 작성했습니다.

다음과 같은 형식으로 리포트를 작성하여 제보를 했습니다.

```
1. Background
해당 issue 내용을 이해하기 위한 배경 지식

2. 개요
취약점의 대략적인 내용

3. 테스트 환경
취약점을 테스트한 환경

4. 시나리오
어떠한 시나리오로 공격하였는지

5. PoC
PoC 코드

6. 결과
결과 분석

7. Root Cause
취약점이 발생한 부분의 코드 분석

8. Patch 방안
Patch 방안 제안
```

다음과 같은 형식에 맞춰 제보했습니다. 제보 내용이 궁금하시면 아래 링크에서 확인하실 수 있습니다.
- [https://github.com/harfbuzz/harfbuzz/security/advisories/GHSA-xvjr-f2r9-c7ww](https://github.com/harfbuzz/harfbuzz/security/advisories/GHSA-xvjr-f2r9-c7ww)

제보 후 취약점이 인정되어 [CVE-2026-22693](https://nvd.nist.gov/vuln/detail/CVE-2026-22693)에 등록되었습니다.