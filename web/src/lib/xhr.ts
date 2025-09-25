export function xhrJson(method: string, url: string, data?: any): Promise<any> {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open(method, url, true);
    xhr.setRequestHeader('Content-Type', 'application/json');
    xhr.onreadystatechange = () => {
      if (xhr.readyState === 4) {
        if (xhr.status >= 200 && xhr.status < 300) {
          try { resolve(xhr.responseText ? JSON.parse(xhr.responseText) : {}); } catch { resolve({}); }
        } else {
          reject(new Error(`${xhr.status} ${xhr.responseText}`));
        }
      }
    };
    xhr.onerror = () => reject(new Error('network_error'));
    xhr.send(data ? JSON.stringify(data) : null);
  });
}

export function xhrGetJson(url: string): Promise<any> { return xhrJson('GET', url); }
export function xhrPostJson(url: string, body: any): Promise<any> { return xhrJson('POST', url, body); }
export function xhrPatchJson(url: string, body: any): Promise<any> { return xhrJson('PATCH', url, body); }
export function xhrPost(url: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open('POST', url, true);
    xhr.onreadystatechange = () => {
      if (xhr.readyState === 4) {
        if (xhr.status >= 200 && xhr.status < 300) resolve();
        else reject(new Error(`${xhr.status} ${xhr.responseText}`));
      }
    };
    xhr.onerror = () => reject(new Error('network_error'));
    xhr.send();
  });
}

// Fetch plain text via XHR (used for OSS markdown reports)
export function xhrGetText(url: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open('GET', url, true);
    xhr.onreadystatechange = () => {
      if (xhr.readyState === 4) {
        if (xhr.status >= 200 && xhr.status < 300) {
          resolve(xhr.responseText || '');
        } else {
          reject(new Error(`${xhr.status} ${xhr.responseText}`));
        }
      }
    };
    xhr.onerror = () => reject(new Error('network_error'));
    xhr.send();
  });
}
