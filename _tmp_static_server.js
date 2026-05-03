const http = require('http');
const fs = require('fs');
const path = require('path');
const root = path.join(process.cwd(), 'frontend', 'ids-frontend');
const mime = {'.html':'text/html','.js':'text/javascript','.css':'text/css','.json':'application/json','.svg':'image/svg+xml','.png':'image/png','.jpg':'image/jpeg','.jpeg':'image/jpeg'};
const server = http.createServer((req,res)=>{
  const reqPath = req.url.split('?')[0];
  let filePath = path.join(root, reqPath === '/' ? 'index.html' : reqPath.replace(/^\//,''));
  if (!filePath.startsWith(root)) { res.writeHead(403); return res.end('forbidden'); }
  fs.readFile(filePath, (err,data)=>{
    if (err) { res.writeHead(404); return res.end('not found'); }
    res.writeHead(200, {'Content-Type': mime[path.extname(filePath)] || 'text/plain', 'Cache-Control':'no-store'});
    res.end(data);
  });
});
server.listen(8123, '127.0.0.1', ()=>console.log('static server ready'));
