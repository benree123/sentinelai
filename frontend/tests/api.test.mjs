import test from 'node:test';
import assert from 'node:assert/strict';
import {api} from '../src/api.ts';

const originalFetch=globalThis.fetch;
globalThis.window=new EventTarget();
const response=(status,body={ok:true})=>new Response(JSON.stringify(body),{status,headers:{'Content-Type':'application/json'}});

test('parallel expired requests share one rotating refresh',async()=>{
 let refreshed=false,refreshCalls=0,expired=0;
 const handler=()=>expired++;
 window.addEventListener('sentinel:expired',handler);
 globalThis.fetch=async(url)=>{
  if(url==='/api/auth/refresh'){refreshCalls++;await new Promise(resolve=>setTimeout(resolve,15));refreshed=true;return response(200)}
  return response(refreshed?200:401,refreshed?{ok:true}:{detail:'Expired'});
 };
 try{
  const results=await Promise.all([api('/dashboard'),api('/events'),api('/incidents')]);
  assert.equal(refreshCalls,1);assert.equal(expired,0);assert.equal(results.length,3);
 }finally{globalThis.fetch=originalFetch;window.removeEventListener('sentinel:expired',handler)}
});

test('a late 401 from the previous token reuses the refreshed session',async()=>{
 let refreshed=false,refreshCalls=0;
 globalThis.fetch=async(url)=>{
  if(url==='/api/auth/refresh'){refreshCalls++;refreshed=true;return response(200)}
  if(!refreshed&&url==='/api/events'){await new Promise(resolve=>setTimeout(resolve,30));return response(401,{detail:'Old token'})}
  return response(refreshed?200:401,refreshed?{ok:true}:{detail:'Expired'});
 };
 try{await Promise.all([api('/events'),api('/dashboard')]);assert.equal(refreshCalls,1)}finally{globalThis.fetch=originalFetch}
});

test('a revoked refresh session emits expiry and rejects the request',async()=>{
 let refreshCalls=0,expired=0;
 const handler=()=>expired++;
 window.addEventListener('sentinel:expired',handler);
 globalThis.fetch=async(url)=>{if(url==='/api/auth/refresh')refreshCalls++;return response(401,{detail:'Session revoked'})};
 try{await assert.rejects(()=>api('/dashboard'),/Session revoked/);assert.equal(refreshCalls,1);assert.equal(expired,1)}finally{globalThis.fetch=originalFetch;window.removeEventListener('sentinel:expired',handler)}
});

test('a non-JSON proxy response shows a readable message',async()=>{
 globalThis.fetch=async()=>new Response('<html>Bad gateway</html>',{status:502,headers:{'Content-Type':'text/html'}});
 try{await assert.rejects(()=>api('/dashboard'),/waking up/)}finally{globalThis.fetch=originalFetch}
});

test('a network failure shows a readable message',async()=>{
 globalThis.fetch=async()=>{throw new TypeError('Failed to fetch')};
 try{await assert.rejects(()=>api('/dashboard'),/waking up/)}finally{globalThis.fetch=originalFetch}
});

test('validation errors show the server message',async()=>{
 globalThis.fetch=async()=>response(422,{detail:[{msg:'Value error, Enter a valid email address'}]});
 try{await assert.rejects(()=>api('/auth/forgot-password'),/^Error: Enter a valid email address$/)}finally{globalThis.fetch=originalFetch}
});
