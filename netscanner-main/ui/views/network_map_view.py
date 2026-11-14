import math
import random
from typing import List, Dict, Any, Optional
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGraphicsView, QGraphicsScene,
    QGraphicsItem, QGraphicsEllipseItem, QGraphicsLineItem, QGraphicsTextItem,
    QPushButton, QLabel, QFrame
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QPointF, QRectF
from PyQt6.QtGui import QPen, QBrush, QColor, QFont, QPainter

class DynamicNodeItem(QGraphicsEllipseItem):
    """
    Interactive, draggable, physics-aware network node.
    Features smooth interpolated movement (lerp) to target coordinates when clicked or moved.
    """
    def __init__(self, x: float, y: float, size: float, title: str, subtext: str, icon: str, color: QColor, device_data: Optional[dict] = None, is_center: bool = False):
        super().__init__(-size / 2, -size / 2, size, size)
        self.setPos(x, y)
        self.target_x = x
        self.target_y = y
        self.size = size
        self.title = title
        self.subtext = subtext
        self.icon = icon
        self.node_color = color
        self.device_data = device_data
        self.is_center = is_center

        self.edges: List['DynamicEdgeItem'] = []

        # Flags for interactive dragging & geometry notifications
        self.setFlags(
            QGraphicsItem.GraphicsItemFlag.ItemIsMovable |
            QGraphicsItem.GraphicsItemFlag.ItemIsSelectable |
            QGraphicsItem.GraphicsItemFlag.ItemSendsGeometryChanges
        )
        self.setAcceptHoverEvents(True)
        self.setCursor(Qt.CursorShape.PointingHandCursor)

        # Styling
        self.setBrush(QBrush(QColor("#1E293B")))
        self.setPen(QPen(color, 3 if is_center else 2))

        # Child Text Items
        self.txt_icon = QGraphicsTextItem(icon, self)
        self.txt_icon.setFont(QFont("Segoe UI Emoji", 16 if is_center else 13))
        self.txt_icon.setDefaultTextColor(QColor("#FFFFFF"))
        self.txt_icon.setPos(-12, -18)

        self.txt_title = QGraphicsTextItem(title[:14], self)
        self.txt_title.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
        self.txt_title.setDefaultTextColor(QColor("#F8FAFC"))
        self.txt_title.setPos(-35, size / 2 + 2)

        self.txt_sub = QGraphicsTextItem(subtext, self)
        self.txt_sub.setFont(QFont("Segoe UI", 8))
        self.txt_sub.setDefaultTextColor(QColor("#94A3B8"))
        self.txt_sub.setPos(-35, size / 2 + 16)

    def set_target_pos(self, tx: float, ty: float):
        self.target_x = tx
        self.target_y = ty

    def update_smooth_movement(self):
        """Smoothly interpolate current position toward target position (click-to-move easing)."""
        curr_pos = self.pos()
        dx = self.target_x - curr_pos.x()
        dy = self.target_y - curr_pos.y()

        if abs(dx) > 0.5 or abs(dy) > 0.5:
            # Smooth lerp interpolation factor (0.15 for fluid movement)
            new_x = curr_pos.x() + dx * 0.15
            new_y = curr_pos.y() + dy * 0.15
            self.setPos(new_x, new_y)

    def add_edge(self, edge: 'DynamicEdgeItem'):
        if edge not in self.edges:
            self.edges.append(edge)

    def itemChange(self, change: QGraphicsItem.GraphicsItemChange, value: Any) -> Any:
        if change == QGraphicsItem.GraphicsItemChange.ItemPositionChange or change == QGraphicsItem.GraphicsItemChange.ItemPositionHasChanged:
            # Update target to current dragged position if being dragged
            if self.isSelected():
                curr = self.scenePos()
                self.target_x = curr.x()
                self.target_y = curr.y()
            for edge in self.edges:
                edge.update_position()
        return super().itemChange(change, value)

    def hoverEnterEvent(self, event):
        self.setBrush(QBrush(QColor("#334155")))
        self.setPen(QPen(QColor("#00F5D4"), 3))
        super().hoverEnterEvent(event)

    def hoverLeaveEvent(self, event):
        self.setBrush(QBrush(QColor("#1E293B")))
        self.setPen(QPen(self.node_color, 3 if self.is_center else 2))
        super().hoverLeaveEvent(event)


class DynamicEdgeItem(QGraphicsLineItem):
    """
    Dynamic edge line connecting two nodes with animated moving traffic particles.
    """
    def __init__(self, source_node: DynamicNodeItem, target_node: DynamicNodeItem, color: QColor):
        super().__init__()
        self.source_node = source_node
        self.target_node = target_node
        self.color = color
        self.particle_progress = random.uniform(0.0, 1.0)
        self.particle_speed = random.uniform(0.02, 0.04)

        self.setPen(QPen(color, 2, Qt.PenStyle.DashLine))
        self.setZValue(-1)

        source_node.add_edge(self)
        target_node.add_edge(self)
        self.update_position()

        # Particle Dot Graphics Item
        self.particle_item = QGraphicsEllipseItem(-5, -5, 10, 10, self)
        self.particle_item.setBrush(QBrush(QColor("#00F5D4") if color == QColor("#22C55E") else QColor("#38BDF8")))
        self.particle_item.setPen(QPen(Qt.GlobalColor.transparent))

    def update_position(self):
        p1 = self.source_node.scenePos()
        p2 = self.target_node.scenePos()
        self.setLine(p1.x(), p1.y(), p2.x(), p2.y())

    def advance_particle(self):
        self.particle_progress += self.particle_speed
        if self.particle_progress > 1.0:
            self.particle_progress = 0.0

        p1 = self.source_node.scenePos()
        p2 = self.target_node.scenePos()

        px = p1.x() + (p2.x() - p1.x()) * self.particle_progress
        py = p1.y() + (p2.y() - p1.y()) * self.particle_progress
        
        self.particle_item.setPos(self.mapFromScene(QPointF(px, py)))


class InteractiveGraphicsView(QGraphicsView):
    """Custom view detecting scene clicks to dynamically move & reorganize node layouts smoothly."""
    canvas_clicked = pyqtSignal(QPointF)

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            scene_pos = self.mapToScene(event.pos())
            # Emit canvas click if clicking on background space
            item = self.scene().itemAt(scene_pos, self.transform())
            if item is None or isinstance(item, QGraphicsLineItem):
                self.canvas_clicked.emit(scene_pos)
        super().mousePressEvent(event)


class NetworkMapView(QWidget):
    node_clicked = pyqtSignal(dict)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.devices = []
        self.nodes: List[DynamicNodeItem] = []
        self.edges: List[DynamicEdgeItem] = []
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        # Dynamic Controls Toolbar
        hdr_layout = QHBoxLayout()
        lbl_title = QLabel("🌐 Dynamic Interactive Topology Map (Click anywhere to dynamically move layout)")
        lbl_title.setStyleSheet("font-weight: bold; font-size: 15px;")

        btn_layout_radial = QPushButton("⭕ Radial Orbit")
        btn_layout_radial.setProperty("class", "PrimaryButton")
        btn_layout_radial.clicked.connect(lambda: self.reposition_nodes_smooth("radial"))

        btn_layout_grid = QPushButton("🔲 Grid Matrix")
        btn_layout_grid.setProperty("class", "SecondaryButton")
        btn_layout_grid.clicked.connect(lambda: self.reposition_nodes_smooth("grid"))

        btn_layout_spiral = QPushButton("🌀 Spiral Cluster")
        btn_layout_spiral.setProperty("class", "SecondaryButton")
        btn_layout_spiral.clicked.connect(lambda: self.reposition_nodes_smooth("spiral"))

        btn_reset_zoom = QPushButton("🔍 Fit Screen")
        btn_reset_zoom.setProperty("class", "SecondaryButton")
        btn_reset_zoom.clicked.connect(self.reset_view)

        hdr_layout.addWidget(lbl_title)
        hdr_layout.addStretch()
        hdr_layout.addWidget(btn_layout_radial)
        hdr_layout.addWidget(btn_layout_grid)
        hdr_layout.addWidget(btn_layout_spiral)
        hdr_layout.addWidget(btn_reset_zoom)
        layout.addLayout(hdr_layout)

        # Interactive View & Scene
        self.scene = QGraphicsScene()
        self.scene.setBackgroundBrush(QBrush(QColor("#0F172A")))
        self.scene.selectionChanged.connect(self._on_scene_selection_changed)

        self.view = InteractiveGraphicsView(self.scene)
        self.view.setRenderHints(QPainter.RenderHint.Antialiasing | QPainter.RenderHint.SmoothPixmapTransform)
        self.view.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)
        self.view.canvas_clicked.connect(self._on_canvas_clicked)
        layout.addWidget(self.view)

        # 60 FPS Animation & Movement Engine Timer
        self.timer = QTimer(self)
        self.timer.timeout.connect(self._on_animation_frame)
        self.timer.start(16) # 60 FPS smooth interpolation

    def set_devices(self, devices: list, gateway_ip: str = "192.168.1.1"):
        self.devices = devices
        self.gateway_ip = gateway_ip
        self.render_topology()

    def render_topology(self, layout_type="radial", center_point: QPointF = QPointF(0, -90)):
        self.scene.clear()
        self.nodes.clear()
        self.edges.clear()

        if not self.devices:
            txt = self.scene.addText("No active devices discovered on the network yet.")
            txt.setDefaultTextColor(QColor("#94A3B8"))
            txt.setFont(QFont("Segoe UI", 14))
            return

        # 1. WAN Cloud Node
        cloud_node = DynamicNodeItem(center_point.x(), center_point.y() - 150, 60, "INTERNET", "WAN Gateway", "🌐", QColor("#38BDF8"), is_center=True)
        self.scene.addItem(cloud_node)
        self.nodes.append(cloud_node)

        # 2. Router Gateway Node
        router_device = next((d for d in self.devices if d.get("device_type") == "Router" or d.get("ip") == self.gateway_ip), None)
        router_ip = router_device.get("ip", self.gateway_ip) if router_device else self.gateway_ip
        
        router_node = DynamicNodeItem(center_point.x(), center_point.y(), 56, "ROUTER / GW", router_ip, "📡", QColor("#22C55E"), device_data=router_device, is_center=True)
        self.scene.addItem(router_node)
        self.nodes.append(router_node)

        # Edge WAN -> Router
        edge_wan = DynamicEdgeItem(cloud_node, router_node, QColor("#38BDF8"))
        self.scene.addItem(edge_wan)
        self.edges.append(edge_wan)

        # 3. Connected Devices
        other_devices = [d for d in self.devices if d != router_device]
        total = len(other_devices)

        if total > 0:
            radius = max(220, total * 28)
            angle_step = (2 * math.pi) / total

            for idx, dev in enumerate(other_devices):
                angle = idx * angle_step
                dx = center_point.x() + radius * math.cos(angle)
                dy = center_point.y() + radius * math.sin(angle) + 50

                self._create_device_node(dx, dy, dev, router_node)

        self.reset_view()

    def _create_device_node(self, x: float, y: float, dev: dict, router_node: DynamicNodeItem):
        is_online = dev.get("status") == "Online"
        color = QColor("#38BDF8") if is_online else QColor("#64748B")

        dtype = dev.get("device_type", "")
        icon = "💻"
        if dtype == "Mobile":
            icon = "📱"
        elif dtype == "Printer":
            icon = "🖨️"
        elif dtype == "Smart TV":
            icon = "📺"
        elif dtype == "IoT Device":
            icon = "🔌"

        node = DynamicNodeItem(x, y, 46, dev.get("hostname", "Host"), dev.get("ip", ""), icon, color, device_data=dev)
        self.scene.addItem(node)
        self.nodes.append(node)

        edge_color = QColor("#22C55E") if is_online else QColor("#EF4444")
        edge = DynamicEdgeItem(router_node, node, edge_color)
        self.scene.addItem(edge)
        self.edges.append(edge)

    def _on_canvas_clicked(self, point: QPointF):
        """When user clicks anywhere on the canvas background, dynamically move all nodes smoothly toward the click point!"""
        self.reposition_nodes_smooth("radial", center_point=point)

    def reposition_nodes_smooth(self, pattern: str = "radial", center_point: Optional[QPointF] = None):
        """Dynamically recalculates target coordinates for all nodes and smoothly animates them to their new positions."""
        if not self.nodes:
            return

        if center_point is None:
            # Keep router node current position as center
            router_node = next((n for n in self.nodes if n.title == "ROUTER / GW"), self.nodes[0])
            center_point = router_node.pos()

        # Update Router target
        router_node = next((n for n in self.nodes if n.title == "ROUTER / GW"), None)
        if router_node:
            router_node.set_target_pos(center_point.x(), center_point.y())

        # Update WAN Cloud target
        cloud_node = next((n for n in self.nodes if n.title == "INTERNET"), None)
        if cloud_node:
            cloud_node.set_target_pos(center_point.x(), center_point.y() - 150)

        # Update Device Nodes target positions based on layout pattern
        device_nodes = [n for n in self.nodes if not n.is_center]
        total = len(device_nodes)

        if total > 0:
            if pattern == "radial":
                radius = max(220, total * 28)
                angle_step = (2 * math.pi) / total
                for idx, node in enumerate(device_nodes):
                    angle = idx * angle_step
                    tx = center_point.x() + radius * math.cos(angle)
                    ty = center_point.y() + radius * math.sin(angle) + 40
                    node.set_target_pos(tx, ty)

            elif pattern == "grid":
                cols = math.ceil(math.sqrt(total))
                spacing = 130
                for idx, node in enumerate(device_nodes):
                    r = idx // cols
                    c = idx % cols
                    tx = center_point.x() + (c - cols / 2) * spacing
                    ty = center_point.y() + 120 + r * spacing
                    node.set_target_pos(tx, ty)

            elif pattern == "spiral":
                for idx, node in enumerate(device_nodes):
                    angle = idx * 0.65
                    radius = 120 + idx * 24
                    tx = center_point.x() + radius * math.cos(angle)
                    ty = center_point.y() + radius * math.sin(angle)
                    node.set_target_pos(tx, ty)

    def _on_animation_frame(self):
        # 1. Update smooth lerp positions for all nodes moving to target coordinates
        for node in self.nodes:
            node.update_smooth_movement()

        # 2. Advance traffic glow particles along connection lines
        for edge in self.edges:
            edge.advance_particle()

    def _on_scene_selection_changed(self):
        selected = self.scene.selectedItems()
        for item in selected:
            if isinstance(item, DynamicNodeItem) and item.device_data:
                self.node_clicked.emit(item.device_data)
                break

    def reset_view(self):
        rect = self.scene.itemsBoundingRect().adjusted(-60, -60, 60, 60)
        self.scene.setSceneRect(rect)
        self.view.fitInView(rect, Qt.AspectRatioMode.KeepAspectRatio)
