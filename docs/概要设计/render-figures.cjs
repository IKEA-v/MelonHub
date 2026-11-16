// PlantUML produces UML; Graphviz lays out the DOT data-flow diagrams locally.
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { createRequire } = require('node:module');

const root = path.resolve(__dirname, '../..');
const jar = process.env.PLANTUML_JAR || path.join(root, '.local/design-tools/plantuml.jar');
if (!fs.existsSync(jar)) throw new Error('Set PLANTUML_JAR to a local PlantUML jar.');
const figures = path.join(__dirname, 'figures');
const sources = fs.readdirSync(figures).filter(n => /^\d.*\.puml$/.test(n));
for (const format of ['svg', 'png']) {
  const inputs = sources.filter(n => !n.includes('-dfd-'));
  const result = spawnSync('java', [
    '-Djava.awt.headless=true', '-DPLANTUML_LIMIT_SIZE=12000',
    '-jar', jar, '-charset', 'UTF-8', `-t${format}`,
    ...inputs.map(n => path.join(figures, n)),
  ], { cwd: root, encoding: 'utf8', windowsHide: true });
  if (result.status !== 0) throw new Error(result.stderr || result.stdout || 'PlantUML failed');
}
const dependencyPath = process.env.MELONHUB_DIAGRAM_NODE_MODULES || path.join(root, '.local/er-tools/package.json');
const dependency = createRequire(path.resolve(dependencyPath));
const { Resvg } = dependency('@resvg/resvg-js');
const { instance } = dependency('@viz-js/viz');
async function renderDataFlow() {
  const viz = await instance();
  for (const source of sources.filter(n => n.includes('-dfd-'))) {
    const dot = fs.readFileSync(path.join(figures, source), 'utf8')
      .replace(/^@startdot\s*/m, '').replace(/^@enddot\s*/m, '')
      .replaceAll('<TD BORDER="1"', '<TD WIDTH="230" BORDER="1"');
    const svg = viz.renderString(dot, { format: 'svg' });
    fs.writeFileSync(path.join(figures, source.replace('.puml', '.svg')), svg);
    const png = new Resvg(svg, {
      font: { loadSystemFonts: true, defaultFontFamily: 'Microsoft YaHei' },
      fitTo: { mode: 'width', value: 3600 }, background: 'white',
    }).render().asPng();
    fs.writeFileSync(path.join(figures, source.replace('.puml', '.png')), png);
  }
  for (const source of sources) {
    const svg = fs.readFileSync(path.join(figures, source.replace('.puml', '.svg')), 'utf8');
    if (/Syntax Error|An error has occurred|Cannot find Graphviz/i.test(svg)) {
      throw new Error(`Diagram error: ${source}`);
    }
  }
  console.log(`Rendered ${sources.length} diagrams (model sources, SVG and PNG).`);
}
renderDataFlow().catch(error => { console.error(error); process.exitCode = 1; });
