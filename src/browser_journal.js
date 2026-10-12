// One owned replica worker per client realm, bounded admission and actual
// response deadlines. Worker death is an unknown outcome, never a fake receipt.
let configuration, active, sequence=0, busy=false;
const keyLeases=new Map();
const waiters=[];
function admit() {
  if(!busy){busy=true;return Promise.resolve();}
  if(waiters.length>=3)return Promise.reject(failed('vault_busy'));
  return new Promise((resolve,reject)=>{
    const entry={resolve:()=>{clearTimeout(entry.timer);resolve();}};
    entry.timer=setTimeout(()=>{
      const index=waiters.indexOf(entry);
      if(index>=0)waiters.splice(index,1);
      reject(failed('vault_busy'));
    },500);
    waiters.push(entry);
  });
}
function release() {
  const next=waiters.shift();
  if(next)next.resolve();else busy=false;
}
function failed(code='vault_dependency_unavailable'){return new Error(code);}
export function configureJournal(worker,module) {
  const urls=[worker,module].map(value=>new URL(value,location.href));
  if(urls.some(url=>url.origin!==location.origin||url.search||url.hash||!url.pathname.endsWith('.js')))throw failed();
  const next=urls.map(url=>url.href);
  if(configuration && configuration.join('|')!==next.join('|'))throw failed();
  configuration=next;
}
function message(worker,data) {
  return new Promise((resolve,reject)=>{
    const id=++sequence;
    const timer=setTimeout(()=>{cleanup();worker.terminate();if(active?.worker===worker)active=undefined;reject(failed());},15000);
    const onMessage=({data})=>{
      if(data.id!==id)return;
      cleanup();
      if(data.error){
        if(data.error!=='vault_busy'){worker.terminate();if(active?.worker===worker)active=undefined;}
        reject(failed(data.error==='vault_busy'?'vault_busy':undefined));
      }else resolve(data.result);
    };
    const onError=()=>{cleanup();worker.terminate();if(active?.worker===worker)active=undefined;reject(failed());};
    function cleanup(){clearTimeout(timer);worker.removeEventListener('message',onMessage);worker.removeEventListener('error',onError);}
    worker.addEventListener('message',onMessage);worker.addEventListener('error',onError);worker.postMessage({...data,id});
  });
}
export async function journalRequest(scope,command) {
  if(!configuration||!/^[a-f0-9]{64}$/.test(scope)||command.length>8*1024*1024)throw failed();
  // Foreground reads/mutations and sync share one worker. Bound the queue
  // and waiting time instead of spuriously failing every overlapping call.
  await admit();
  try {
    if(!active||active.scope!==scope) {
      active?.worker.terminate();
      const worker=new Worker(configuration[0],{type:'module'});
      active={scope,worker};
      try{await message(worker,{action:'initialize',scope,module:configuration[1]});}
      catch(error){worker.terminate();active=undefined;throw error;}
    }
    return await message(active.worker,{action:'execute',command});
  } finally {release();}
}
export function releaseKey(id) {const lease=keyLeases.get(id);if(lease){keyLeases.delete(id);lease.controller.abort();lease.release();}}
export function acquireKey(id,scope) {
  if(!/^[a-f0-9-]{36}$/.test(id)||!/^[a-f0-9]{64}$/.test(scope)||keyLeases.has(id)||keyLeases.size>=4) return Promise.reject(failed());
  return new Promise((resolve,reject)=>{
    const controller=new AbortController();let release;
    const held=new Promise(done=>{release=done;});const lease={controller,release};keyLeases.set(id,lease);
    const timer=setTimeout(()=>{controller.abort();reject(failed('vault_busy'));},500);
    navigator.locks.request('nds-vault-key:'+scope,{signal:controller.signal},async lock=>{
      if(!lock||!keyLeases.has(id))throw failed();clearTimeout(timer);resolve();await held;
    }).catch(()=>{if(keyLeases.get(id)===lease)keyLeases.delete(id);release();reject(failed('vault_busy'));});
    held.then(()=>clearTimeout(timer));
  });
}

// This is a browser retention preference, not a backup or a promise that the
// user cannot clear site data. Request once per client and report the result.
export async function requestPersistence() {
  try {
    if(!navigator.storage?.persisted||!navigator.storage?.persist)return false;
    if(await navigator.storage.persisted())return true;
    await navigator.storage.persist();
    return await navigator.storage.persisted();
  } catch {return false;}
}
