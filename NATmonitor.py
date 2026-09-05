
"""
##################################################################
# Created By: Kobie Hazon                                        #
# Date: 04/05/2017                                               #
# Name: NATmonitor                                               #
# Version: 1.0                                                   #
# Linux Tested Versions: Centos 7 64 bit                         #
# Python Tested Versions: 2.7.10 32-bit                          #
# Python Environment  : PyCharm 2017.1.1                         #
##################################################################
"""

import wx
import wx.grid
import threading
import Queue
import time
import datetime


class NATmonitor(wx.Frame, threading.Thread):

    def __init__(self):
        threading.Thread.__init__(self)

    def run(self):
        self.app = wx.PySimpleApp()
        wx.Frame.__init__(self, None, -1, 'NATmonitor', size=(775, 605),
                          style=wx.DEFAULT_FRAME_STYLE & (~wx.CLOSE_BOX) & (~wx.MAXIMIZE_BOX) ^ wx.RESIZE_BORDER)
        self.panel = wx.Panel(self, pos=(100, 100))
        self.grid = wx.grid.Grid(self.panel, pos=(100, 100))
        self.grid_setup()
        self.start_background('refresh_grid')
        self.app.MainLoop()

    def grid_setup(self):
        self.grid.CreateGrid(14, 6)
        self.grid.SetDefaultCellAlignment(wx.ALIGN_CENTER, wx.ALIGN_CENTER)
        self.grid.SetDefaultCellFont(wx.Font(10, wx.FONTFAMILY_MODERN, 0, wx.FONTWEIGHT_NORMAL))
        self.grid.SetDefaultCellTextColour('NAVY')
        for j in range(14):
            self.grid.SetCellFont(j, 5, wx.Font(8, wx.FONTFAMILY_MODERN, 0, wx.FONTWEIGHT_NORMAL))
        sizer = wx.BoxSizer(wx.VERTICAL)
        sizer.Add(self.grid, 1, wx.EXPAND)
        self.panel.SetSizer(sizer)
        for i in range(15):
            self.grid.SetRowSize((i - 1), 40)
        for j in range(6):
            self.grid.SetColSize((j - 1), 120)
        self.Show()
        self.grid.EnableDragGridSize(False)
        self.grid.DisableDragColSize()
        self.grid.DisableDragRowSize()
        self.grid.SetColLabelValue(0, 'Type')
        self.grid.SetColLabelValue(1, 'Source IP')
        self.grid.SetColLabelValue(2, 'Source Port')
        self.grid.SetColLabelValue(3, 'Destination Ip')
        self.grid.SetColLabelValue(4, 'Destination Port')
        self.grid.SetColLabelValue(5, 'Time')
        self.grid.SetRowLabelValue(0, 'Incoming:')
        for i in range(1, 7):
            self.grid.SetRowLabelValue(i, str(i))
        self.grid.SetRowLabelValue(7, 'Outgoing:')
        for i in range(1, 7):
            self.grid.SetRowLabelValue((i + 7), str(i))

        self.grid.SetLabelBackgroundColour('AQUAMARINE')
        self.grid.SetLabelTextColour('Purple')
        self.grid.SetLabelFont(wx.Font(10, wx.FONTFAMILY_ROMAN, 0, wx.FONTWEIGHT_MAX))

    def refresh_grid(self):
        while True:
            if not entry_buffer.empty():
                x = entry_buffer.get()
                self.add_value(x[0], x[1])

    def add_value(self, direction, pkt_tuple):
        try:
            if direction == 'Incoming':
                self.pull_down('in')
                for j in range(5):
                    self.grid.SetCellValue(1, j, pkt_tuple[j])
                self.grid.SetCellValue(1, 5, datetime.datetime.now().strftime("%I:%M:%S%p"))

            if direction == 'Outgoing':
                self.pull_down('out')
                for j in range(5):
                    self.grid.SetCellValue(8, j, pkt_tuple[j])
                self.grid.SetCellValue(8, 5, datetime.datetime.now().strftime("%I:%M:%S%p"))

            time.sleep(0.7)
        except:
            pass

    def pull_down(self, in_or_out):
        if in_or_out == 'in':
            for i in range(7, 1, -1):
                for j in range(6):
                    self.grid.SetCellValue(i, j, self.grid.GetCellValue((i-1), j))

            for j in range(6):
                self.grid.SetCellValue(1, j, '')

        if in_or_out == 'out':
            for i in range(15, 8, -1):
                for j in range(6):
                    if i == 14:
                        self.grid.SetCellValue(i, j, '')
                    else:
                        self.grid.SetCellValue(i, j, self.grid.GetCellValue((i-1), j))

            for j in range(6):
                self.grid.SetCellValue(8, j, '')

        for j in range(6):
            self.grid.SetCellValue(0, j, '')
        for j in range(6):
            self.grid.SetCellValue(7, j, '')

    def start_background(self, func):  # helper method to run a function in another thread
        thread = threading.Thread(target=getattr(self, func))
        thread.setDaemon(True)
        thread.start()


def start_nat_monitor():
    t.setDaemon(True)
    t.start()


def gui_entry(direction, pkt_tuple):
    entry_buffer.put((direction, pkt_tuple))


entry_buffer = Queue.Queue(100)
t = NATmonitor()
