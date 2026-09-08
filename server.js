const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
let pg = null;
try { pg = require('pg'); } catch {}

const PORT = Number(process.env.PORT || 8787);
const ROOT = __dirname;
const DATA_DIR = path.join(ROOT, 'data');
const SMS_FILE = path.join(DATA_DIR, 'sms-inbox.json');
const TOKEN_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
const DATABASE_URL = process.env.DATABASE_URL || '';
const USE_DB = !!(DATABASE_URL && pg);
fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(SMS_FILE)) fs.writeFileSync(SMS_FILE, '[]');

const pool = USE_DB ? new pg.Pool({ connectionString: DATABASE_URL, ssl: process.env.PGSSLMODE === 'require' ? { rejectUnauthorized: false } : undefined }) : null;

function json(res,status,body,headers={}) { res.writeHead(status,{ 'Content-Type':'application/json; charset=utf-8','Access-Control-Allow-Origin':'*','Access-Control-Allow-Headers':'Content-Type, X-HarborPOS-Token, Authorization','Access-Control-Allow-Methods':'GET,POST,PUT,OPTIONS',...headers }); res.end(JSON.stringify(body)); }
function collect(req){return new Promise((resolve,reject)=>{let d='';req.on('data',c=>d+=c);req.on('end',()=>resolve(d));req.on('error',reject);});}
function readSms(){try{return JSON.parse(fs.readFileSync(SMS_FILE,'utf8'));}catch{return[];}}
function writeSms(rows){fs.writeFileSync(SMS_FILE,JSON.stringify(rows.slice(-500),null,2));}
function normalize(body){const p=body||{};const payload=p.payload||p.data||p;const message=payload.message||payload.text||payload.body||payload.content||p.message||p.text||'';const sender=payload.sender||payload.from||p.sender||p.from||'';const recipient=payload.recipient||payload.to||p.recipient||p.to||'';const timestamp=payload.scts||payload.receivedAt||payload.timestamp||p.scts||p.receivedAt||new Date().toISOString();const tag=payload.tag||p.tag||'';const messageId=payload.messageId||p.messageId||p.id||crypto.createHash('sha256').update(`${sender}|${message}|${timestamp}`).digest('hex').slice(0,24);return{id:messageId,sender,recipient,message:String(message),receivedAt:timestamp,tag};}
function parseMpesa(text){const t=String(text||'').replace(/\s+/g,' ').trim();const amount=(t.match(/(?:received|paid|sent|payment).*?K(?:ES)?\s*([0-9][0-9,]*(?:\.\d{1,2})?)/i)||t.match(/K(?:ES)?\s*([0-9][0-9,]*(?:\.\d{1,2})?)/i)||[])[1];const ref=(t.match(/\b([A-Z]{2,10}\d{5,})\b/i)||[])[1]||'';const from=(t.match(/from\s+(.+?)(?:\s+on\s+|\s+at\s+|\.\s*$)/i)||[])[1]||'';return{isMpesa:/m-?pesa|safaricom|mpesa/i.test(t),amount:amount?Number(amount.replace(/,/g,'')):null,reference:ref.toUpperCase(),customer:from.trim()};}

function b64url(x){return Buffer.from(x).toString('base64url');}
function signToken(payload){const body=b64url(JSON.stringify(payload));const sig=crypto.createHmac('sha256',TOKEN_SECRET).update(body).digest('base64url');return `${body}.${sig}`;}
function verifyToken(token){try{const [body,sig]=String(token||'').split('.');if(!body||!sig)return null;const expSig=crypto.createHmac('sha256',TOKEN_SECRET).update(body).digest('base64url');if(!crypto.timingSafeEqual(Buffer.from(sig),Buffer.from(expSig)))return null;const p=JSON.parse(Buffer.from(body,'base64url').toString('utf8'));if(!p.exp||Date.now()>p.exp)return null;return p;}catch{return null;}}
function auth(req){const h=req.headers.authorization||'';if(h.startsWith('Bearer '))return verifyToken(h.slice(7));return verifyToken(req.headers['x-harborpos-token']);}
function hashPassword(password){const salt=crypto.randomBytes(16).toString('hex');const hash=crypto.scryptSync(String(password),salt,64).toString('hex');return `scrypt:${salt}:${hash}`;}
function checkPassword(password,stored){if(!stored)return false;const [alg,salt,hash]=String(stored).split(':');if(alg!=='scrypt'||!salt||!hash)return false;const actual=crypto.scryptSync(String(password),salt,64).toString('hex');return crypto.timingSafeEqual(Buffer.from(actual,'hex'),Buffer.from(hash,'hex'));}

async function dbLogin(email,password){
  const client=await pool.connect(); try{
    let r=await client.query(`select u.id,u.business_id,u.name,u.email,u.password_hash,u.role,u.level_id,u.active, coalesce(json_agg(ub.branch_id) filter (where ub.branch_id is not null),'[]') as branch_ids from users u left join user_branches ub on ub.user_id=u.id where lower(u.email)=lower($1) group by u.id`,[email]);
    if(!r.rowCount)return null; const u=r.rows[0]; if(!u.active||!checkPassword(password,u.password_hash))return null;
    const b=await client.query(`select id,name,code,location,active from branches where business_id=$1 and active=true order by name`,[u.business_id]);
    const bs=await client.query(`select state from business_state where business_id=$1`,[u.business_id]);
    return {user:{id:u.id,name:u.name,email:u.email,role:u.role,level:Number(u.level_id||1),branchIds:(u.branch_ids||[]).map(String),active:u.active!==false},businessId:u.business_id,branches:b.rows,state:bs.rowCount?bs.rows[0].state:null};
  } finally{client.release();}
}

async function dbSaveState(session,state){const client=await pool.connect();try{await client.query(`insert into business_state(business_id,state,updated_at) values($1,$2::jsonb,now()) on conflict(business_id) do update set state=excluded.state,updated_at=now()`,[session.businessId,JSON.stringify(state)]);return true;}finally{client.release();}}
async function dbLoadState(session){const r=await pool.query(`select state from business_state where business_id=$1`,[session.businessId]);return r.rowCount?r.rows[0].state:null;}

const localUsers=[
 {id:'u1',name:'System Admin',email:'admin@harborpos.local',password:'HarborPOS123!',role:'Owner',level:1,branchIds:['b1'],active:true,businessId:'demo-business'},
 {id:'u2',name:'General Manager',email:'manager@harborpos.local',password:'HarborPOS123!',role:'General Manager',level:2,branchIds:['b1'],active:true,businessId:'demo-business'},
 {id:'u3',name:'Cashier',email:'cashier@harborpos.local',password:'HarborPOS123!',role:'Cashier',level:4,branchIds:['b1'],active:true,businessId:'demo-business'}
];
const localStateFile=path.join(DATA_DIR,'cloud-state.json');
function localLoad(){try{return JSON.parse(fs.readFileSync(localStateFile,'utf8'));}catch{return null;}}
function localSave(state){fs.writeFileSync(localStateFile,JSON.stringify(state,null,2));}

const server=http.createServer(async(req,res)=>{
  const u=new URL(req.url,`http://${req.headers.host}`);
  if(req.method==='OPTIONS')return json(res,204,{});
  try{
    if(u.pathname==='/api/health')return json(res,200,{ok:true,service:'HarborPOS',cloudMode:USE_DB?'postgresql':'server-persistent-file',time:new Date().toISOString()});
    if(u.pathname==='/api/auth/login'&&req.method==='POST'){
      const body=JSON.parse(await collect(req)||'{}'); const email=String(body.email||'').trim().toLowerCase(); const password=String(body.password||'');
      if(USE_DB){const result=await dbLogin(email,password);if(!result)return json(res,401,{ok:false,error:'Invalid email or password'});const token=signToken({userId:result.user.id,businessId:result.businessId,exp:Date.now()+1000*60*60*24*30});return json(res,200,{ok:true,token,user:result.user,branches:result.branches,state:result.state,cloud:true});}
      const u2=localUsers.find(x=>x.email===email&&x.password===password&&x.active!==false);if(!u2)return json(res,401,{ok:false,error:'Invalid email or password'});const token=signToken({userId:u2.id,businessId:u2.businessId,exp:Date.now()+1000*60*60*24*30});return json(res,200,{ok:true,token,user:{id:u2.id,name:u2.name,email:u2.email,role:u2.role,level:u2.level,branchIds:u2.branchIds,active:true},cloud:false});
    }
    if(u.pathname==='/api/cloud/state'&&(req.method==='GET'||req.method==='PUT')){
      const session=auth(req);if(!session)return json(res,401,{ok:false,error:'Authentication required'});
      if(req.method==='GET'){
        if(USE_DB){const state=await dbLoadState(session);return json(res,200,{ok:true,state,updatedAt:new Date().toISOString(),cloud:true});}
        return json(res,200,{ok:true,state:localLoad(),cloud:false});
      }
      const state=JSON.parse(await collect(req)||'{}');
      if(USE_DB){await dbSaveState(session,state);return json(res,200,{ok:true,saved:true,updatedAt:new Date().toISOString()});}
      localSave(state);return json(res,200,{ok:true,saved:true,updatedAt:new Date().toISOString()});
    }
    if(u.pathname==='/api/smsenabler/incoming'&&(req.method==='POST'||req.method==='GET')){const token=process.env.SMS_ENABLER_TOKEN||'';if(token&&req.headers['x-harborpos-token']!==token&&u.searchParams.get('token')!==token)return json(res,401,{ok:false,error:'Invalid webhook token'});let body={};if(req.method==='POST'){const raw=await collect(req);try{body=JSON.parse(raw||'{}')}catch{body=Object.fromEntries(new URLSearchParams(raw));}}else body=Object.fromEntries(u.searchParams.entries());const sms=normalize(body);if(!sms.message)return json(res,400,{ok:false,error:'SMS message missing'});const rows=readSms();if(!rows.some(x=>x.id===sms.id)){rows.push({...sms,mpesa:parseMpesa(sms.message)});writeSms(rows);}return json(res,200,{ok:true,received:true,messageId:sms.id});}
    if(u.pathname==='/api/mpesa/messages'&&req.method==='GET')return json(res,200,{ok:true,messages:readSms()});
    if(u.pathname==='/api/mpesa/test'&&req.method==='POST'){let body={};try{body=JSON.parse(await collect(req)||'{}')}catch{}const sms={id:'TEST-'+Date.now(),sender:body.sender||'MPESA',recipient:body.recipient||'',message:body.message||'',receivedAt:new Date().toISOString(),tag:'test'};const rows=readSms();rows.push({...sms,mpesa:parseMpesa(sms.message)});writeSms(rows);return json(res,200,{ok:true,sms});}
    let filePath=path.join(ROOT,u.pathname==='/'?'index.html':u.pathname.replace(/^\//,''));if(!filePath.startsWith(ROOT)||!fs.existsSync(filePath)||fs.statSync(filePath).isDirectory())return json(res,404,{error:'Not found'});const ext=path.extname(filePath);const type=ext==='.js'?'application/javascript':ext==='.css'?'text/css':ext==='.html'?'text/html':ext==='.json'?'application/json':'application/octet-stream';res.writeHead(200,{'Content-Type':type});fs.createReadStream(filePath).pipe(res);
  }catch(e){console.error(e);return json(res,500,{ok:false,error:e.message});}
});
server.listen(PORT,()=>console.log(`HarborPOS running on http://localhost:${PORT} | cloud=${USE_DB?'postgresql':'server-file'}`));
