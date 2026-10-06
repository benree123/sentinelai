export type User = {username:string; role:'admin'|'manager'|'analyst'|'viewer';email?:string;display_name?:string};
export type SecurityEvent = {simulated?:boolean;id:number; external_id:string; kind:string; service:string; actor:string; source_ip:string; message:string; occurred_at:string};
export type Incident = {id:number; reference:string; title:string; rule:string; severity:string; score:number; status:string; assigned_to:string|null; version:number; explanation:string; evidence_count:number; created_at:string; updated_at:string; evidence?:SecurityEvent[]; notes?:{id:number;author:string;body:string;created_at:string}[]};
export type Dashboard = {events:number;events_today:number; active_incidents:number; critical:number; investigating:number; severity:Record<string,number>; trend:number[]; rules:{id:string;kind:string;score:number;threshold:number;window_minutes:number}[]};
export type Briefing = {mode:string;model:string|null;summary:string;hypotheses:string[];next_steps:string[];evidence_ids:number[];limitations:string};
export type AuditEntry = {id:number;actor:string;action:string;target:string;detail:string;created_at:string};
// Coordinate rotating refresh credentials across parallel dashboard requests.
let refreshInFlight:Promise<boolean>|null=null;
let authGeneration=0;
function refreshSession(){
 if(!refreshInFlight){
  refreshInFlight=fetch('/api/auth/refresh',{method:'POST',credentials:'same-origin',headers:{'X-Sentinel-Request':'1'}})
   .then(response=>{if(response.ok){authGeneration++;return true}return false})
   .finally(()=>{refreshInFlight=null});
 }
 return refreshInFlight;
}
export async function api<T>(path:string, options:RequestInit={}):Promise<T> {
 const generationAtStart=authGeneration;
 const send=()=>fetch('/api'+path,{...options,credentials:'same-origin',headers:{'Content-Type':'application/json','X-Sentinel-Request':'1',...options.headers}});
 let response=await send();
 if(response.status===401 && (!path.startsWith('/auth/') || ['/auth/me','/auth/logout','/auth/sessions'].some(p=>path.startsWith(p)))){
  // A late response from the old token can arrive after another request refreshed.
  const refreshed=authGeneration!==generationAtStart || await refreshSession();
  if(refreshed)response=await send();
  else window.dispatchEvent(new Event('sentinel:expired'));
 }
 const data=await response.json();
 if(!response.ok)throw new Error(typeof data.detail==='string'?data.detail:'Please check the submitted values.');
 return data as T;
}
export function relativeDate(iso:string){const minutes=Math.max(0,Math.floor((Date.now()-Date.parse(iso))/60000));return minutes<1?'Just now':minutes<60?`${minutes}m ago`:`${Math.floor(minutes/60)}h ago`}
export function label(value:string){return value.replaceAll('_',' ')}
