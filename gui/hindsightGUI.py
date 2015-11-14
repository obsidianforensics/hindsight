#!/usr/bin/python
# -*- coding: utf-8 -*-

import wx, os, sys, subprocess, threading
from gui import *


# Trying to get PyInstaller to find my resource files
def resource_path(relative_path):
    """ Get absolute path to resource, works for dev and for PyInstaller """
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)

################################################################################
class RedirectText:
    """"""
    
    #---------------------------------------------------------------------------
    def __init__(self, txtCtrl):
        self.out = txtCtrl
        
    #---------------------------------------------------------------------------
    def write(self, string):
        self.out.AppendText(string)
        
################################################################################
class procThread (threading.Thread):
    """"""

    #---------------------------------------------------------------------------
    def __init__(self, cmd):
        threading.Thread.__init__(self)
        self.cmd = cmd
        
    #---------------------------------------------------------------------------
    def run(self):
        proc = subprocess.Popen(self.cmd, stdout=subprocess.PIPE, shell=True, stderr=subprocess.STDOUT,
                                stdin=subprocess.PIPE)
        print "\n"
        while True:
            l = proc.stdout.readline()
            # wx.Yield()
            if l == '' and proc.poll() is not None:
                break
            if l:
                print l[:-2]
        MainApp.b_process.Enable()
        
################################################################################
class DefaultDropTarget(wx.FileDropTarget):
    """"""
    
    #---------------------------------------------------------------------------
    def __init__(self, window):
        """Constructor"""
        wx.FileDropTarget.__init__(self)
        self.window = window
        
    #---------------------------------------------------------------------------
    def OnDropFiles(self, x, y, filename):
        self.window.updateDefaultText(filename[0])
            
################################################################################
class OutputDropTarget(wx.FileDropTarget):
    """"""
    
    #---------------------------------------------------------------------------
    def __init__(self, window):
        """Constructor"""
        wx.FileDropTarget.__init__(self)
        self.window = window
        
    #---------------------------------------------------------------------------
    def OnDropFiles(self, x, y, filename):
        self.window.updateOutputText(filename[0])
            
################################################################################
class LogDropTarget(wx.FileDropTarget):
    """"""
    
    #---------------------------------------------------------------------------
    def __init__(self, window):
        """Constructor"""
        wx.FileDropTarget.__init__(self)
        self.window = window
        
    #---------------------------------------------------------------------------
    def OnDropFiles(self, x, y, filename):
        self.window.updateLogText(filename[0])

################################################################################
class MainWindow(mainFrame):
    """ Implementing MainFrameBase """
    
    #---------------------------------------------------------------------------
    def __init__(self, parent):
        """ Constructor """
        mainFrame.__init__(self, parent)
        self.t_default.SetDropTarget(DefaultDropTarget(self)) 
        self.t_output.SetDropTarget(OutputDropTarget(self)) 
        self.t_log.SetDropTarget(LogDropTarget(self))
        self.t_default.SetFocus() 
        icon = wx.EmptyIcon()
        icon.CopyFromBitmap(wx.Bitmap(resource_path("h.ico"), wx.BITMAP_TYPE_ANY))
        self.SetIcon(icon)
        self.c_timezone.SetSelection(0)
        self.Show()
        self.flush = sys.stdout.flush()
        self.redir = RedirectText(self.t_commandWindow)        
        sys.stdout = self.redir
   
    #---------------------------------------------------------------------------
    def updateDefaultText(self, text):
        self.t_default.Clear()
        self.t_default.WriteText(text)
        
    #---------------------------------------------------------------------------
    def updateOutputText(self, text):
        self.t_output.Clear()
        self.t_output.WriteText(text)
        
    #---------------------------------------------------------------------------
    def updateLogText(self, text):
        self.t_log.Clear()
        self.t_log.WriteText(text)
    
    #---------------------------------------------------------------------------
    def browseDefault(self, event):
        selectDirDialog = wx.DirDialog(self, "Choose Default Chrome Directory", "", wx.DD_DEFAULT_STYLE)
        if selectDirDialog.ShowModal() == wx.ID_CANCEL:
            return
        self.updateDefaultText(selectDirDialog.GetPath())
    
    #---------------------------------------------------------------------------
    def browseOutput(self, event):
        selectFileDialog = wx.FileDialog(self, "Save Output File", "", "", "Excel Workbook (*.xlsx)|*.xlsx|" "SQLite Database (*.sqlite)|*.sqlite|" "JavaScript Object Notation (*.json)|*.json", wx.FD_SAVE | wx.FD_OVERWRITE_PROMPT)     
        if selectFileDialog.ShowModal() == wx.ID_CANCEL:
            return
        self.updateOutputText(selectFileDialog.GetPath())
    
    #---------------------------------------------------------------------------
    def browseLog(self, event):
        selectFileDialog = wx.FileDialog(self, "Save Log File", "", "", "Log file (*.log)|*.log", wx.FD_SAVE | wx.FD_OVERWRITE_PROMPT)     
        if selectFileDialog.ShowModal() == wx.ID_CANCEL:
            return
        self.updateLogText(selectFileDialog.GetPath())
        
    #---------------------------------------------------------------------------
    def reset(self, event):
        self.t_default.Clear()
        self.t_output.Clear()
        self.t_log.Clear()
        self.c_timezone.SetSelection(0)
        self.t_commandWindow.ShowPosition(self.t_commandWindow.GetLastPosition())
        self.t_commandWindow.Clear()
        self.t_commandWindow.WriteText("\n Hindsight - Internet history forensics for Google Chrome/Chromium. \n\n"
                                       " Select the Chrome Profile folder (commonly named 'Default') to parse using the \n"
                                       " option in the right panel.  \n\n"
                                       " Chrome Profile Directory Locations:\n\n"
                                       "       WinXP: <userdir>\\Local Settings\\Application Data\\Google\\Chrome\n"
                                       "               \\User Data\\Default\n"
                                       "   Vista/7/8: <userdir>\\AppData\\Local\\Google\\Chrome\\User Data\\Default\n"
                                       "       Linux: <userdir>/.config/google-chrome/Default/\n"
                                       "        OS X: <userdir>/Library/Application Support/Google/Chrome/Default/\n"
                                       "         iOS: Applications\\com.google.chrome.ios\\Library\\Application Support\n"
                                       "               \\Google\\Chrome\\Default")
        
    #---------------------------------------------------------------------------
    def process(self, event):
        self.b_process.Disable()
        ext = self.t_output.GetValue()[-4:]
        if ext == "lite":
            format = " -f sqlite"
            outputFile = self.t_output.GetValue()[:-7]
        elif ext == "json":
            format = " -f json"
            outputFile = self.t_output.GetValue()[:-5]
        elif ext == "xlsx":
            format = " -f xlsx"
            outputFile = self.t_output.GetValue()[:-5]
        else:
            format = " -f xlsx"
            outputFile = self.t_output.GetValue()
        hs_path = resource_path("hindsight.exe")
        cmd = hs_path + " -i \"" + self.t_default.GetValue() + "\" -o \"" + outputFile + "\""
        if self.t_log.GetValue() != '':
            cmd += " -l \"" + self.t_log.GetValue() + "\""
        cmd += format        
        tzIndex = self.c_timezone.GetSelection()
        tz = "UTC"
        if tzIndex == 0:
            tz = "UTC"
        elif tzIndex == 1:
            tz = "US/Eastern"
        elif tzIndex == 2:
            tz = "US/Central"
        elif tzIndex == 3:
            tz = "US/Arizona"
        elif tzIndex == 4:
            tz = "US/Mountain"
        elif tzIndex == 5:
            tz = "US/Pacific"
        elif tzIndex == 6:
            tz = "US/Alaska"
        elif tzIndex == 7:
            tz = "US/Hawaii"
        elif tzIndex == 8:
            tz = "US/Samoa"
        cmd += " -t " + tz
        
        runCmd = procThread(cmd)
        runCmd.start()

        #while process.poll() is None:
        #    l = process.stdout.readline()
        #    print l[:-2]
        #print process.stdout.read()
        #self.b_process.Enable()
        
        #print "\n"
        #while True:
        #    line = process.stdout.readline()
        #    wx.Yield()
        #    print line[:-2]            
        #    if not line:
        #        break
        
    #---------------------------------------------------------------------------    
    def onCloseMainFrame(self, event):
        """ Close main frame """
        self.Destroy()
        
#-------------------------------------------------------------------------------
if __name__ == '__main__':
    app = wx.App(0)
    MainApp = MainWindow(None)
    app.MainLoop()
