// Isolated synthetic UI fixture. Never calls a management server. Not used by npm start.
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { resolve, extname } from 'node:path';
const base = resolve('public');
const rows = ['EDGE-01', 'EDGE-02'].map(Name => ({ Name, 'Allowed clients': Name === 'EDGE-01' ? 'AnyHost' : '192.0.2.10' }));
const checks = [
  {id:'admin.identity', title:'Administrator Identity and Access Control', category:'Administrator Identity and Access Control', status:'needs-review', severity:'high', recommendation:'Review administrator roles and restrict privileges to the access required.', details:'Synthetic UI test: two administrative accounts require review.'},
  {id:'mgmt.firewall', title:'Protect Management Server Behind A Firewall', category:'Management Plane Protection', status:'manual', severity:'high', recommendation:'Verify that the management server is protected by an appropriate access policy.', details:'Validate administrative access against your network design.'},
  {id:'policy.gateway-object-status', title:'Gateway Object SIC Status', category:'Gateway Object SIC Status', status:'pass', severity:'high', evidenceTable:{columns:['Name','SIC status'], rows:rows.map(({Name})=>({Name,'SIC status':'communicating'}))}},
  {id:'gaia.allowed-hosts', title:'Gaia Allowed Host Access', category:'Gaia OS Hardening', status:'remediation-required', severity:'high', recommendation:'Limit Gaia trusted client access to approved management hosts and networks.', details:'Review the allowed clients configured on this gateway.', evidenceTable:{columns:['Name','Allowed clients'],rows}},
  {id:'gaia.password', title:'Password Policy Hardening', category:'Gaia OS Hardening', status:'needs-review', severity:'high', recommendation:'Configure password complexity, age, and reuse controls.', evidenceTable:{columns:['Name','Password policy'],rows:rows.map(({Name})=>({Name,'Password policy':'Review configuration'}))}},
  {id:'updates.jumbo', title:'Upgrade To Latest Recommended Jumbo Hotfix Accumulator', category:'Updates, Health, and Ongoing Protection', status:'needs-review', severity:'medium', recommendation:'Review the recommended Jumbo Hotfix before planning an upgrade.', evidenceTable:{columns:['Name','Installed version','Recommended update'], rows:rows.map(({Name})=>({Name,'Installed version':'R82.10 Take 24','Recommended update':'Manually verify'}))}},
  {id:'gaia.ntp', title:'Configure Reliable Time Synchronization', category:'Gaia OS Hardening', status:'pass', severity:'medium', evidenceTable:{columns:['Name','State'],rows:rows.map(({Name})=>({Name,State:'Configured'}))}},
  {id:'gaia.lom', title:'Restrict Out-Of-Band Management', category:'Gaia OS Hardening', status:'manual', severity:'medium', recommendation:'Verify out-of-band access is restricted to approved administrators.',evidenceTable:{columns:['Name','State'],rows:rows.map(({Name})=>({Name,State:'Manual verification'}))}}
];
const scan = { scannedAt:new Date().toISOString(), managementObjectName:'MGMT-LAB', gatewayTargets:['EDGE-01','EDGE-02'], checks, summary:{'needs-review':3,'remediation-required':1,manual:2,pass:2}, commandLog:[],commandResults:{} };
let allDomains = false;
createServer(async(req,res)=>{
  try {
    if(req.url.startsWith('/api/')) {
      res.setHeader('Content-Type','application/json');
      if(req.url==='/api/health') return res.end(JSON.stringify({ok:true}));
      if(req.url==='/api/login') {
        let body = ''; for await (const chunk of req) body += chunk;
        allDomains = JSON.parse(body).host === 'mds.synthetic.invalid';
        return res.end(JSON.stringify({sessionId:allDomains?'synthetic-mds':'synthetic-test',baseUrl:'Synthetic UI fixture — no live connection',user:'test',moraMode:allDomains,domains:[]}));
      }
      if(req.url==='/api/scan') {
        await new Promise(resolve => setTimeout(resolve, 3000));
        return res.end(JSON.stringify(allDomains ? {...scan,moraMode:true,domains:[
          {uid:'domain-a',name:'Synthetic Domain A',scan},
          {uid:'domain-b',name:'Synthetic Domain B',scan:{...scan,managementObjectName:'MGMT-SECOND'}},
          {uid:'domain-failed',name:'Synthetic unavailable domain',error:'Synthetic collection failure. Reconnect and retry the scan.'}
        ]} : scan));
      }
      if(req.url==='/api/logout') return res.end('{}');
      return res.end(JSON.stringify({error:'This synthetic preview does not perform actions or exports.'}));
    }
    const path = resolve(base, '.' + new URL(req.url,'http://localhost').pathname.replace(/^\/$/,'/index.html'));
    if(!path.startsWith(base+'/')) {res.writeHead(403);return res.end();}
    res.setHeader('Content-Type', {'.html':'text/html','.js':'text/javascript','.css':'text/css','.png':'image/png'}[extname(path)]||'application/octet-stream');
    res.end(await readFile(path));
  } catch {res.writeHead(404);res.end();}
}).listen(3299,'127.0.0.1',()=>console.log('Synthetic-only preview: http://127.0.0.1:3299'));
