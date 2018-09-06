const {session, app, BrowserWindow} = require('electron')
  
  // Keep a global reference of the window object, if you don't, the window will
  // be closed automatically when the JavaScript object is garbage collected.
  let win
  
  const D_WIDTH = 800;
  const D_HEIGHT = D_WIDTH;

  function createWindow () {
    // Create the browser window.
    win = new BrowserWindow({
      width: D_WIDTH, D_HEIGHT: 600,
      
      webPreferences: { 
        nodeIntegration: true,
        contextIsolation: false, 
        webSecurity: true,
        allowRunningInsecureContent: false,
        sandbox: false
      }
    })
    win.loadFile('client/index.html')
  
    // Open the DevTools.
    //win.webContents.openDevTools()

    win.on('closed', () => {
      win = null
    })
  }

  app.on('ready', createWindow)

  app.on('window-all-closed', () => {
    if (process.platform !== 'darwin') {
      app.quit()
    }
  })
  
  app.on('activate', () => {
    if (win === null) {
      createWindow()
    }
  })