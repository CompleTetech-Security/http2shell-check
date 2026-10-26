// Optional developer-only renderer. Uses Playwright already provided by mcp/playwright.
// Does not add a checker dependency or contact external sites.
const { chromium } = require('/app/node_modules/playwright');
const fs = require('node:fs');
(async () => {
  const browser = await chromium.launch({headless:true, channel:'chromium', args:['--no-sandbox']});
  const page = await browser.newPage({viewport:{width:1440,height:1100}, deviceScaleFactor:1});
  const requests=[];
  await page.route('**/*', route => {
    const url=route.request().url();
    if(url.startsWith('file:') || url.startsWith('data:')) return route.continue();
    requests.push(url); return route.abort();
  });
  const evidence=[];
  for(const [name,theme,width,media] of [
    ['light','light',1440,'screen'],['dark','dark',1440,'screen'],
    ['narrow','light',390,'screen'],['print','light',1100,'print']]) {
    await page.setViewportSize({width,height:1100});
    await page.emulateMedia({colorScheme:theme,media});
    await page.goto('file:///work/docs/example-report.html');
    await page.screenshot({path:`/work/docs/images/report-${name}.png`,fullPage:false});
    const layout=await page.evaluate(()=>({width:innerWidth,scrollWidth:document.documentElement.scrollWidth,
      cards:document.querySelectorAll('article').length,images:[...document.images].every(i=>i.complete&&i.naturalWidth>0),
      overflow:[...document.querySelectorAll('article,dd,td,h1,h3,.pill')].filter(e=>e.scrollWidth>e.clientWidth+2).map(e=>e.tagName)}));
    evidence.push({name,...layout});
    if(layout.scrollWidth>width || !layout.images || layout.overflow.length) throw new Error('Layout failure '+JSON.stringify(layout));
    if(name==='print') await page.pdf({path:'/work/docs/example-report.pdf',format:'A4',printBackground:true,margin:{top:'12mm',bottom:'12mm',left:'12mm',right:'12mm'}});
  }
  const logo=fs.readFileSync('/work/assets/logo.png').toString('base64');
  await page.emulateMedia({colorScheme:'light',media:'screen'});
  await page.setViewportSize({width:1600,height:450});
  await page.setContent(`<html><head><style>*{box-sizing:border-box}body{margin:0;background:#101e36;color:#eef3ff;font-family:Arial,sans-serif}.banner{height:450px;padding:65px 80px;display:flex;align-items:center;gap:75px;border-bottom:12px solid #5b8edb}.logo{background:white;border-radius:22px;width:220px;padding:18px}.tag{color:#a8c8ff;font-size:19px;letter-spacing:5px}h1{font-size:66px;letter-spacing:-2px;margin:18px 0}p{font-size:25px;color:#c4d1e7;margin:0;line-height:1.5}.cve{font-size:17px;color:#a8c8ff;margin-top:25px}</style></head><body><div class="banner"><img class="logo" src="data:image/png;base64,${logo}"><div><div class="tag">COMPLETETECH LLC / SECURITY TOOLS</div><h1>Brotli exposure, with evidence.</h1><p>HTTP2Shell Check · Offline component assessment<br>Native libraries · Runtimes · Python · Java · Proxies</p><div class="cve">CVE-2026-111497 · No payloads · No dependencies</div></div></div></body></html>`);
  await page.screenshot({path:'/work/docs/images/banner.png'});
  fs.writeFileSync('/work/docs/visual-checks.json',JSON.stringify({externalRequests:requests,layouts:evidence},null,2)+'\n');
  await browser.close();
})().catch(error=>{console.error(error);process.exitCode=1;});
