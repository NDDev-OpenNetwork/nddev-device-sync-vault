// One owned replica worker per client realm, bounded admission and actual
// response deadlines. Worker death is an unknown outcome, never a fake receipt.
let configuration, active, sequence=0, busy=false;
const keyLeases=new Map();
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
  if(busy)throw failed('vault_busy');
  busy=true;
  try {
    if(!active||active.scope!==scope) {
      active?.worker.terminate();
      const worker=new Worker(configuration[0],{type:'module'});
      active={scope,worker};
      try{await message(worker,{action:'initialize',scope,module:configuration[1]});}
      catch(error){worker.terminate();active=undefined;throw error;}
    }
    return await message(active.worker,{action:'execute',command});
  } finally {busy=false;}
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
