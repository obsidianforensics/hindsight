# -*- coding: utf-8 -*- 

###########################################################################
## Python code generated with wxFormBuilder (version Jun 17 2015)
## http://www.wxformbuilder.org/
##
## PLEASE DO "NOT" EDIT THIS FILE!
###########################################################################

import wx
import wx.xrc

# import tempfile, sys
# sys.stdout = tempfile.TemporaryFile()
# sys.stderr = tempfile.TemporaryFile()

###########################################################################
## Class mainFrame
###########################################################################

class mainFrame ( wx.Frame ):
	
	def __init__( self, parent ):
		wx.Frame.__init__ ( self, parent, id = wx.ID_ANY, title = u"Hindsight", pos = wx.DefaultPosition, size = wx.Size( 926,370 ), style = wx.CAPTION|wx.CLOSE_BOX|wx.MAXIMIZE_BOX|wx.MINIMIZE_BOX|wx.SYSTEM_MENU|wx.TAB_TRAVERSAL )
		
		self.SetSizeHintsSz( wx.DefaultSize, wx.DefaultSize )
		
		bSizer1 = wx.BoxSizer( wx.VERTICAL )
		
		self.m_splitter2 = wx.SplitterWindow( self, wx.ID_ANY, wx.DefaultPosition, wx.DefaultSize, wx.SP_3D )
		self.m_splitter2.Bind( wx.EVT_IDLE, self.m_splitter2OnIdle )
		
		self.m_panel3 = wx.Panel( self.m_splitter2, wx.ID_ANY, wx.DefaultPosition, wx.DefaultSize, wx.TAB_TRAVERSAL )
		bSizer6 = wx.BoxSizer( wx.VERTICAL )
		
		self.m_splitter1 = wx.SplitterWindow( self.m_panel3, wx.ID_ANY, wx.DefaultPosition, wx.DefaultSize, wx.SP_3D )
		self.m_splitter1.Bind( wx.EVT_IDLE, self.m_splitter1OnIdle )
		
		self.m_panel2 = wx.Panel( self.m_splitter1, wx.ID_ANY, wx.DefaultPosition, wx.DefaultSize, wx.TAB_TRAVERSAL )
		bSizer13 = wx.BoxSizer( wx.HORIZONTAL )
		
		bSizer12 = wx.BoxSizer( wx.VERTICAL )
		
		sbSizer5 = wx.StaticBoxSizer( wx.StaticBox( self.m_panel2, wx.ID_ANY, wx.EmptyString ), wx.VERTICAL )
		
		self.t_commandWindow = wx.TextCtrl( sbSizer5.GetStaticBox(), wx.ID_ANY, u"\n Hindsight - Internet history forensics for Google Chrome/Chromium.\n\n Select the Chrome profile folder (commonly named 'Default') to parse using the \n option in the right panel.  \n\n Chrome Profile Directory Locations:\n\n       WinXP: <userdir>\\Local Settings\\Application Data\\Google\\Chrome\n               \\User Data\\Default\n   Vista/7/8: <userdir>\\AppData\\Local\\Google\\Chrome\\User Data\\Default\n       Linux: <userdir>/.config/google-chrome/Default/\n        OS X: <userdir>/Library/Application Support/Google/Chrome/Default/\n         iOS: Applications\\com.google.chrome.ios\\Library\\Application Support\\\n               Google\\Chrome\\Default", wx.DefaultPosition, wx.DefaultSize, wx.TE_MULTILINE|wx.TE_READONLY|wx.TE_RICH|wx.NO_BORDER )
		self.t_commandWindow.SetFont( wx.Font( wx.NORMAL_FONT.GetPointSize(), 76, 90, 90, False, wx.EmptyString ) )
		self.t_commandWindow.SetForegroundColour( wx.SystemSettings.GetColour( wx.SYS_COLOUR_3DLIGHT ) )
		self.t_commandWindow.SetBackgroundColour( wx.SystemSettings.GetColour( wx.SYS_COLOUR_CAPTIONTEXT ) )
		
		sbSizer5.Add( self.t_commandWindow, 1, wx.ALL|wx.EXPAND, 5 )
		
		
		bSizer12.Add( sbSizer5, 1, wx.EXPAND|wx.ALL, 5 )
		
		
		bSizer13.Add( bSizer12, 2, wx.EXPAND, 5 )
		
		bSizer3 = wx.BoxSizer( wx.VERTICAL )
		
		sbSizer2 = wx.StaticBoxSizer( wx.StaticBox( self.m_panel2, wx.ID_ANY, u"Chrome Profile Directory (typically 'Default')" ), wx.VERTICAL )
		
		bSizer5 = wx.BoxSizer( wx.HORIZONTAL )
		
		self.t_default = wx.TextCtrl( sbSizer2.GetStaticBox(), wx.ID_ANY, wx.EmptyString, wx.DefaultPosition, wx.DefaultSize, 0 )
		bSizer5.Add( self.t_default, 1, wx.ALL, 5 )
		
		self.b_browseDefault = wx.Button( sbSizer2.GetStaticBox(), wx.ID_ANY, u"Browse", wx.DefaultPosition, wx.DefaultSize, 0 )
		bSizer5.Add( self.b_browseDefault, 0, wx.ALL, 5 )
		
		
		sbSizer2.Add( bSizer5, 1, wx.EXPAND, 5 )
		
		
		bSizer3.Add( sbSizer2, 0, wx.EXPAND|wx.TOP|wx.RIGHT|wx.LEFT, 5 )
		
		sbSizer3 = wx.StaticBoxSizer( wx.StaticBox( self.m_panel2, wx.ID_ANY, u"Output File Name (optional)" ), wx.VERTICAL )
		
		bSizer8 = wx.BoxSizer( wx.HORIZONTAL )
		
		self.t_output = wx.TextCtrl( sbSizer3.GetStaticBox(), wx.ID_ANY, wx.EmptyString, wx.DefaultPosition, wx.DefaultSize, 0 )
		bSizer8.Add( self.t_output, 1, wx.ALL, 5 )
		
		self.b_browseOutput = wx.Button( sbSizer3.GetStaticBox(), wx.ID_ANY, u"Browse", wx.DefaultPosition, wx.DefaultSize, 0 )
		bSizer8.Add( self.b_browseOutput, 0, wx.ALL, 5 )
		
		
		sbSizer3.Add( bSizer8, 1, wx.EXPAND, 5 )
		
		
		bSizer3.Add( sbSizer3, 0, wx.EXPAND|wx.TOP|wx.RIGHT|wx.LEFT, 5 )
		
		sbSizer4 = wx.StaticBoxSizer( wx.StaticBox( self.m_panel2, wx.ID_ANY, u"Log File (optional)" ), wx.VERTICAL )
		
		bSizer9 = wx.BoxSizer( wx.HORIZONTAL )
		
		self.t_log = wx.TextCtrl( sbSizer4.GetStaticBox(), wx.ID_ANY, wx.EmptyString, wx.DefaultPosition, wx.DefaultSize, 0 )
		bSizer9.Add( self.t_log, 1, wx.ALL, 5 )
		
		self.b_browseLog = wx.Button( sbSizer4.GetStaticBox(), wx.ID_ANY, u"Browse", wx.DefaultPosition, wx.DefaultSize, 0 )
		bSizer9.Add( self.b_browseLog, 0, wx.ALL, 5 )
		
		
		sbSizer4.Add( bSizer9, 1, wx.EXPAND, 5 )
		
		
		bSizer3.Add( sbSizer4, 0, wx.EXPAND|wx.TOP|wx.RIGHT|wx.LEFT, 5 )
		
		bSizer10 = wx.BoxSizer( wx.VERTICAL )
		
		sbSizer6 = wx.StaticBoxSizer( wx.StaticBox( self.m_panel2, wx.ID_ANY, u"Timezone" ), wx.VERTICAL )
		
		c_timezoneChoices = [ u"(UTC) Coordinated Universal Time", u"(UTC-05:00) US/Eastern", u"(UTC-06:00) US/Central", u"(UTC-07:00) US/Arizona", u"(UTC-07:00) US/Mountain", u"(UTC-08:00) US/Pacific", u"(UTC-09:00) US/Alaska", u"(UTC-10:00) US/Hawaii", u"(UTC-11:00) US/Samoa" ]
		self.c_timezone = wx.Choice( sbSizer6.GetStaticBox(), wx.ID_ANY, wx.DefaultPosition, wx.DefaultSize, c_timezoneChoices, 0 )
		self.c_timezone.SetSelection( 0 )
		sbSizer6.Add( self.c_timezone, 0, wx.EXPAND|wx.ALL, 5 )
		
		
		bSizer10.Add( sbSizer6, 0, wx.EXPAND|wx.ALL, 5 )
		
		
		bSizer3.Add( bSizer10, 1, wx.EXPAND, 5 )
		
		bSizer16 = wx.BoxSizer( wx.HORIZONTAL )
		
		self.b_reset = wx.Button( self.m_panel2, wx.ID_ANY, u"Reset", wx.DefaultPosition, wx.DefaultSize, 0 )
		bSizer16.Add( self.b_reset, 0, wx.ALL|wx.ALIGN_CENTER_VERTICAL, 5 )
		
		self.b_process = wx.Button( self.m_panel2, wx.ID_ANY, u"                  Process                  ", wx.DefaultPosition, wx.DefaultSize, 0 )
		bSizer16.Add( self.b_process, 1, wx.ALL|wx.ALIGN_CENTER_HORIZONTAL|wx.ALIGN_CENTER_VERTICAL, 5 )
		
		
		bSizer3.Add( bSizer16, 0, wx.EXPAND, 5 )
		
		
		bSizer13.Add( bSizer3, 1, wx.EXPAND, 5 )
		
		
		self.m_panel2.SetSizer( bSizer13 )
		self.m_panel2.Layout()
		bSizer13.Fit( self.m_panel2 )
		self.m_splitter1.Initialize( self.m_panel2 )
		bSizer6.Add( self.m_splitter1, 1, wx.EXPAND, 5 )
		
		
		self.m_panel3.SetSizer( bSizer6 )
		self.m_panel3.Layout()
		bSizer6.Fit( self.m_panel3 )
		self.m_splitter2.Initialize( self.m_panel3 )
		bSizer1.Add( self.m_splitter2, 1, wx.EXPAND, 5 )
		
		
		self.SetSizer( bSizer1 )
		self.Layout()
		
		self.Centre( wx.BOTH )
		
		# Connect Events
		self.Bind( wx.EVT_CLOSE, self.onCloseMainFrame )
		self.b_browseDefault.Bind( wx.EVT_BUTTON, self.browseDefault )
		self.b_browseOutput.Bind( wx.EVT_BUTTON, self.browseOutput )
		self.b_browseLog.Bind( wx.EVT_BUTTON, self.browseLog )
		self.b_reset.Bind( wx.EVT_BUTTON, self.reset )
		self.b_process.Bind( wx.EVT_BUTTON, self.process )
	
	def __del__( self ):
		pass
	
	
	# Virtual event handlers, overide them in your derived class
	def onCloseMainFrame( self, event ):
		event.Skip()
	
	def browseDefault( self, event ):
		event.Skip()
	
	def browseOutput( self, event ):
		event.Skip()
	
	def browseLog( self, event ):
		event.Skip()
	
	def reset( self, event ):
		event.Skip()
	
	def process( self, event ):
		event.Skip()
	
	def m_splitter2OnIdle( self, event ):
		self.m_splitter2.SetSashPosition( 0 )
		self.m_splitter2.Unbind( wx.EVT_IDLE )
	
	def m_splitter1OnIdle( self, event ):
		self.m_splitter1.SetSashPosition( 0 )
		self.m_splitter1.Unbind( wx.EVT_IDLE )
	

