import express from 'express';
import cors from 'cors';
import fs from 'fs';
import path from 'path';
import multer from 'multer';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import { fileURLToPath } from 'url';
dotenv.config();
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET || 'change-this-secret';
const DATA_DIR = path.join(__dirname,'data');
const UPLOAD_DIR = path.join(DATA_DIR,'uploads');
fs.mkdirSync(UPLOAD_DIR,{recursive:true});
if(!fs.existsSync(path.join(DATA_DIR,'designs.json'))) fs.writeFileSync(path.join(DATA_DIR,'designs.json'),'[]');

const ADMINS = [
  { user: (process.env.ADMIN_SRIHARI_USER||'srihari').toLowerCase(), plain: process.env.ADMIN_SRIHARI_PASS, hash: process.env.ADMIN_SRIHARI_HASH },
  { user: (process.env.ADMIN_KATHIRVEL_USER||'KATHIRVEL').toLowerCase(), plain: process.env.ADMIN_KATHIRVEL_PASS, hash: process.env.ADMIN_KATHIRVEL_HASH }
];
for(let a of ADMINS){ if(!a.hash && a.plain) a.hash = bcrypt.hashSync(a.plain,10); }

app.use(cors());
app.use(express.json({limit:'20mb'}));
app.use(express.static(path.join(__dirname,'public')));
app.use('/data/uploads', express.static(UPLOAD_DIR));

const storage = multer.diskStorage({destination:UPLOAD_DIR,filename:(req,file,cb)=>cb(null,Date.now()+'-'+Math.random().toString(36).slice(2)+path.extname(file.originalname))});
const upload = multer({storage,limits:{fileSize:10*1024*1024}});

function auth(req,res,next){
  const token = (req.headers['authorization']||'').replace('Bearer ','');
  if(!token) return res.status(401).json({error:'No token'});
  try{ req.adminUser = jwt.verify(token,JWT_SECRET).user; next(); }catch{ res.status(401).json({error:'Invalid token'}); }
}

app.get('/api/designs',(req,res)=> res.json(JSON.parse(fs.readFileSync(path.join(DATA_DIR,'designs.json'),'utf-8'))));
app.post('/api/designs',auth,(req,res)=>{ fs.writeFileSync(path.join(DATA_DIR,'designs.json'),JSON.stringify(req.body,null,2)); res.json({ok:true}); });
app.post('/api/upload',auth,upload.single('file'),(req,res)=> res.json({url:`/data/uploads/${req.file.filename}`}));
app.post('/api/admin/login',async(req,res)=>{
  const {user,pass}=req.body;
  const admin=ADMINS.find(a=>a.user===user.toLowerCase());
  if(!admin?.hash) return res.status(401).json({error:'Invalid login'});
  const ok=await bcrypt.compare(pass,admin.hash);
  if(!ok) return res.status(401).json({error:'Invalid login'});
  const token=jwt.sign({user:admin.user},JWT_SECRET,{expiresIn:'7d'});
  res.json({ok:true,token,user:admin.user});
});
app.get('/api/admin/me',auth,(req,res)=> res.json({ok:true,user:req.adminUser}));
app.get('/api/health',(req,res)=> res.json({ok:true,admins:ADMINS.map(a=>a.user)}));
app.get('*',(req,res)=> res.sendFile(path.join(__dirname,'public','index.html')));
app.listen(PORT,()=>console.log('Running on '+PORT));
