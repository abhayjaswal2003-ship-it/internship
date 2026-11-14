from PyQt6.QtWidgets import QWidget, QVBoxLayout
import pyqtgraph as pg

class TrafficChartWidget(QWidget):
    def __init__(self, title: str = "Real-Time Bandwidth Usage", parent=None):
        super().__init__(parent)
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        pg.setConfigOption('background', '#1E293B')
        pg.setConfigOption('foreground', '#94A3B8')

        self.plot_widget = pg.PlotWidget(title=title)
        self.plot_widget.showGrid(x=True, y=True, alpha=0.3)
        self.plot_widget.setLabel('left', 'Speed', units='KB/s')
        self.plot_widget.setLabel('bottom', 'Time', units='s')
        self.plot_widget.addLegend(offset=(10, 10))

        self.upload_curve = self.plot_widget.plot(name="Upload", pen=pg.mkPen(color='#38BDF8', width=2))
        self.download_curve = self.plot_widget.plot(name="Download", pen=pg.mkPen(color='#22C55E', width=2))

        self.upload_data = [0.0] * 60
        self.download_data = [0.0] * 60

        layout.addWidget(self.plot_widget)

    def update_data(self, upload_kb: float, download_kb: float):
        self.upload_data.pop(0)
        self.upload_data.append(upload_kb)

        self.download_data.pop(0)
        self.download_data.append(download_kb)

        self.upload_curve.setData(self.upload_data)
        self.download_curve.setData(self.download_data)
