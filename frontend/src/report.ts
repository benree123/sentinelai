type Report={reference:string;download_url:string};
export function downloadReport(report:Report){
 const link=document.createElement('a');link.href=report.download_url;link.download=report.reference+'-report.md';document.body.appendChild(link);link.click();link.remove();
}
export type {Report};
