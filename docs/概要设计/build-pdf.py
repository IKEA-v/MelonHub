"""Build the course PDF from the maintained Markdown and diagram images."""
from __future__ import annotations

import argparse
import html
import os
import re
from pathlib import Path

from PIL import Image as PILImage
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A3, A4, landscape
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    BaseDocTemplate, Frame, Image, NextPageTemplate, PageBreak, PageTemplate,
    Paragraph, Spacer, Table, TableStyle,
)
from reportlab.platypus.tableofcontents import TableOfContents

HERE = Path(__file__).resolve().parent
DOCS = HERE.parent
QA = DOCS.parent / 'tmp/pdfs/outline-design'
QA.mkdir(parents=True, exist_ok=True)
font_dir = Path(os.environ.get('WINDIR', 'C:/Windows')) / 'Fonts'
font_regular = os.environ.get('MELONHUB_PDF_FONT', str(font_dir / 'simhei.ttf'))
font_bold = os.environ.get('MELONHUB_PDF_BOLD_FONT', font_regular)
pdfmetrics.registerFont(TTFont('ZH', font_regular))
pdfmetrics.registerFont(TTFont('ZH-Bold', font_bold))
pdfmetrics.registerFontFamily('ZH', normal='ZH', bold='ZH-Bold', italic='ZH', boldItalic='ZH-Bold')

styles = getSampleStyleSheet()
for name in ('Normal', 'BodyText', 'Title', 'Heading1', 'Heading2', 'Heading3'):
    styles[name].fontName = 'ZH'
styles.add(ParagraphStyle('BodyZH', fontName='ZH', fontSize=10, leading=17,
                          wordWrap='CJK', spaceAfter=7, splitLongWords=True))
styles.add(ParagraphStyle('H1ZH', parent=styles['BodyZH'], fontSize=16,
                          leading=23, spaceBefore=5, spaceAfter=14, keepWithNext=True))
styles.add(ParagraphStyle('H2ZH', parent=styles['BodyZH'], fontSize=12.5,
                          leading=19, spaceBefore=10, spaceAfter=8, keepWithNext=True))
styles.add(ParagraphStyle('H3ZH', parent=styles['BodyZH'], fontSize=10.5,
                          leading=17, spaceBefore=8, spaceAfter=5, keepWithNext=True))
styles.add(ParagraphStyle('CellZH', fontName='ZH', fontSize=8.2, leading=12.4,
                          wordWrap='CJK', splitLongWords=True))
styles.add(ParagraphStyle('HeaderZH', parent=styles['CellZH'], textColor=colors.HexColor('#17212a')))
styles.add(ParagraphStyle('CaptionZH', parent=styles['BodyZH'], fontSize=9,
                          leading=14, spaceAfter=7, keepWithNext=True))
styles.add(ParagraphStyle('FigureCaption', parent=styles['BodyZH'], fontSize=12,
                          leading=19, alignment=TA_CENTER, spaceAfter=12))
styles.add(ParagraphStyle('CoverTitle', parent=styles['BodyZH'], fontSize=27,
                          leading=40, alignment=TA_CENTER, spaceAfter=18))
styles.add(ParagraphStyle('CoverSmall', parent=styles['BodyZH'], fontSize=12,
                          leading=23, alignment=TA_CENTER, spaceAfter=12))
styles.add(ParagraphStyle('AppendixBody', parent=styles['BodyZH'], fontSize=9,
                          leading=14, spaceAfter=5))
styles.add(ParagraphStyle('AppendixH2', parent=styles['H2ZH'], fontSize=11,
                          leading=16, spaceBefore=7, spaceAfter=5))
styles.add(ParagraphStyle('AppendixH3', parent=styles['H3ZH'], fontSize=10,
                          leading=15, spaceBefore=5, spaceAfter=4))


def inline(text: str) -> str:
    text = re.sub(r'\[([^\]]+)\]\([^)]+\)', r'\1', text)
    text = text.replace('`', '')
    text = html.escape(text)
    text = re.sub(r'\*\*(.+?)\*\*', r'<b>\1</b>', text)
    return text


class DesignDoc(BaseDocTemplate):
    def __init__(self, target: Path):
        super().__init__(str(target), pagesize=A4, leftMargin=46, rightMargin=46,
                         topMargin=48, bottomMargin=43,
                         title='MelonHub 概要设计说明书', author='MelonHub 项目组')
        self.heading_counter = 0
        self.figure_pages = []
        definitions = [
            ('body', A4, 46, 48, 46, 43),
            ('figure-p', A4, 32, 40, 32, 35),
            ('figure-l', landscape(A4), 32, 40, 32, 35),
            ('figure-a3', A3, 36, 44, 36, 36),
        ]
        templates = []
        for name, size, left, top, right, bottom in definitions:
            frame = Frame(left, bottom, size[0]-left-right, size[1]-top-bottom,
                          id=name, leftPadding=0, bottomPadding=0, rightPadding=0, topPadding=0)
            templates.append(PageTemplate(id=name, frames=[frame], pagesize=size,
                                          onPage=self.decorate))
        self.addPageTemplates(templates)

    def decorate(self, canvas, doc):
        width, height = doc.pageTemplate.pagesize
        canvas.saveState()
        canvas.setFont('ZH', 8)
        canvas.setFillColor(colors.HexColor('#5f6870'))
        if doc.page > 1:
            canvas.drawString(36, height-26, 'MelonHub  概要设计说明书  /  代码基线 V7')
            canvas.drawRightString(width-36, 21, str(doc.page))
        canvas.restoreState()

    def afterFlowable(self, flowable):
        if isinstance(flowable, Paragraph) and hasattr(flowable, 'toc_level'):
            key = flowable.bookmark_key
            self.canv.bookmarkPage(key)
            self.canv.addOutlineEntry(flowable.getPlainText(), key, level=flowable.toc_level, closed=False)
            self.notify('TOCEntry', (flowable.toc_level, flowable.getPlainText(), self.page, key))


def table(rows: list[list[str]], number: int) -> Table:
    n = len(rows[0])
    total = A4[0]-92
    # Matrices allocate more width to identities and relationships.
    weights = {
        2: [0.22, 0.78],
        3: [0.23, 0.33, 0.44],
        4: [0.18, 0.35, 0.28, 0.19],
        5: [0.13, 0.26, 0.26, 0.22, 0.13],
        6: [0.085, 0.14, 0.17, 0.20, 0.205, 0.20],
    }.get(n, [1/n]*n)
    widths = [total*w/sum(weights) for w in weights]
    data = [[Paragraph(inline(c), styles['HeaderZH' if i == 0 else 'CellZH'])
             for c in row] for i, row in enumerate(rows)]
    out = Table(data, colWidths=widths, repeatRows=1, hAlign='LEFT', splitByRow=1)
    out.setStyle(TableStyle([
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#e9edf0')),
        ('LINEBELOW', (0,0), (-1,0), 0.65, colors.HexColor('#63717b')),
        ('LINEBELOW', (0,1), (-1,-1), 0.3, colors.HexColor('#cbd1d6')),
        ('LEFTPADDING', (0,0), (-1,-1), 5),
        ('RIGHTPADDING', (0,0), (-1,-1), 5),
        ('TOPPADDING', (0,0), (-1,-1), 6),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
    ]))
    return out


def figure(caption: str, image_path: Path) -> list:
    with PILImage.open(image_path) as src:
        width, height = src.size
    if image_path.name.startswith('09-'):
        template, paper = 'figure-a3', A3
    elif width / height > 1.25:
        template, paper = 'figure-l', landscape(A4)
    else:
        template, paper = 'figure-p', A4
    avail_w, avail_h = paper[0]-72, paper[1]-132
    factor = min(avail_w/width, avail_h/height)
    img = Image(str(image_path), width=width*factor, height=height*factor)
    img.hAlign = 'CENTER'
    return [NextPageTemplate(template), PageBreak(),
            Paragraph(inline(caption), styles['FigureCaption']), img,
            NextPageTemplate('body'), PageBreak()]


def parse_markdown(path: Path, prefix: str = '') -> list:
    lines = path.read_text(encoding='utf-8').splitlines()
    out, i, table_number = [], 0, 0
    first_top = True
    compact = False
    while i < len(lines):
        line = lines[i].strip()
        if not line:
            i += 1
            continue
        match = re.match(r'!\[([^\]]+)\]\(([^)]+)\)', line)
        if match:
            # Adjacent figure pages switch templates directly, avoiding an empty body page.
            if len(out) >= 2 and isinstance(out[-1], PageBreak) and isinstance(out[-2], NextPageTemplate):
                del out[-2:]
            out.extend(figure(match[1], path.parent/match[2]))
            i += 1
            continue
        if line.startswith('|'):
            rows = []
            while i < len(lines) and lines[i].strip().startswith('|'):
                row = [x.strip() for x in lines[i].strip().strip('|').split('|')]
                if not all(re.fullmatch(r':?-+:?', x) for x in row):
                    rows.append(row)
                i += 1
            if any(len(row) != len(rows[0]) for row in rows):
                raise ValueError(f'Inconsistent Markdown table near line {i}: {path}')
            table_number += 1
            out.extend([table(rows, table_number), Spacer(1, 9)])
            continue
        heading = re.match(r'^(#{1,4})\s+(.+)$', line)
        if heading:
            level, text = len(heading[1]), heading[2]
            if level == 1:
                i += 1
                continue
            if prefix:
                level += 1
                text = re.sub(r'^(\d+)\s+', lambda m: f'B.{m[1]} ', text)
            if text.startswith('附录 A'):
                compact = True
            if level == 2:
                if not first_top and not (out and isinstance(out[-1], PageBreak)):
                    out.append(PageBreak())
                first_top = False
            style = {2:'H1ZH', 3:'H2ZH', 4:'H3ZH'}[level]
            if compact and level in (3, 4):
                style = {3:'AppendixH2', 4:'AppendixH3'}[level]
            p = Paragraph(inline(text), styles[style])
            if level <= 3:
                p.toc_level = level-2
                p.bookmark_key = f'{prefix}h{i}'
            out.append(p)
            i += 1
            continue
        if re.match(r'^表\s+[0-9B]', line):
            out.append(Paragraph(inline(line), styles['CaptionZH']))
            i += 1
            continue
        paragraph = [line]
        i += 1
        while i < len(lines) and lines[i].strip() and not re.match(r'[#|!]', lines[i].strip()):
            paragraph.append(lines[i].strip())
            i += 1
        out.append(Paragraph(inline(' '.join(paragraph)), styles['AppendixBody' if compact else 'BodyZH']))
    return out


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, default=DOCS/'MelonHub_概要设计说明书.pdf')
    args = parser.parse_args()
    story = [Spacer(1, 125), Paragraph('MelonHub', styles['CoverTitle']),
             Paragraph('概要设计说明书', styles['CoverTitle']), Spacer(1, 24),
             Paragraph('统一权限平台 · 软件级 RBAC0', styles['CoverSmall']),
             Paragraph('版本 1.0　　2026 年 11 月 12 日', styles['CoverSmall']),
             Paragraph('编制依据：当前源码与 Flyway V7', styles['CoverSmall']),
             Spacer(1, 35),
             Paragraph('包含总体架构、设计模型、接口与全局数据、部署、\n轻量级 ATAM 评估及需求追溯。', styles['CoverSmall']),
             Paragraph('原规格差异及代码基线需求见第 9 节和附录 B。', styles['CoverSmall']),
             PageBreak(), Paragraph('目录', styles['H1ZH'])]
    toc = TableOfContents()
    toc.levelStyles = [
        ParagraphStyle('toc1', fontName='ZH', fontSize=10, leading=17, spaceBefore=4),
        ParagraphStyle('toc2', fontName='ZH', fontSize=9, leading=14, leftIndent=16),
    ]
    story.extend([toc, PageBreak()])
    story.extend(parse_markdown(DOCS/'概要设计说明书.md'))
    appendix_heading = Paragraph('附录 B 代码基线需求与原规格对照', styles['H1ZH'])
    appendix_heading.toc_level = 0
    appendix_heading.bookmark_key = 'appendix-b'
    story.extend([PageBreak(), appendix_heading,
                  Paragraph('本附录随正文一并交付，CF/CN 的完整定义及证据见下表。', styles['BodyZH'])])
    # The appendix source has its own numbered headings; shift them to appendix labels.
    appendix = parse_markdown(HERE/'需求基线校正.md', prefix='baseline-')
    story.extend(appendix)
    doc = DesignDoc(args.output)
    doc.multiBuild(story)
    print(f'PDF built: {args.output} ({doc.page} pages)')


if __name__ == '__main__':
    main()
