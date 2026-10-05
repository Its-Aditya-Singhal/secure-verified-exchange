// Runs before first paint: theme (no flash) and the release switch.
// RELEASE: set to 'live' once the installers are in /downloads and the SVX
// service is online. While it is 'soon', every download button says
// "Coming soon" and the download page explains why.
(function(){
  var RELEASE='soon';
  var d=document.documentElement,t;
  try{t=localStorage.getItem('svx-theme')}catch(e){}
  d.setAttribute('data-theme',t==='light'?'light':'dark');
  d.setAttribute('data-release',RELEASE);
  d.classList.add('js');
})();
