import math
import random
from PySide6.QtWidgets import QGraphicsView, QGraphicsScene, QGraphicsEllipseItem, QGraphicsLineItem, QGraphicsItem, QWidget, QVBoxLayout, QLabel
from PySide6.QtCore import Qt, QTimer, QPointF, QRectF
from PySide6.QtGui import QColor, QPen, QBrush, QPainter, QRadialGradient

class NeuralNode(QGraphicsEllipseItem):
    def __init__(self, node_id, label, radius=6):
        super().__init__(-radius, -radius, radius * 2, radius * 2)
        self.node_id = node_id
        self.label = label
        self.radius = radius
        self.setFlag(QGraphicsItem.ItemIsSelectable, True)
        self.setFlag(QGraphicsItem.ItemIsMovable, True)
        self.setFlag(QGraphicsItem.ItemSendsGeometryChanges, True)
        self.setAcceptHoverEvents(True)
        self.setZValue(10)
        
        # Velocity for physics
        self.vx = 0.0
        self.vy = 0.0
        
        # Appearance
        self.default_color = QColor(255, 255, 255, 200)
        self.hover_color = QColor(0, 229, 255, 255)
        self.setBrush(QBrush(self.default_color))
        self.setPen(QPen(Qt.NoPen))
        
        self.edges = []
        
    def add_edge(self, edge):
        self.edges.append(edge)

    def itemChange(self, change, value):
        if change == QGraphicsItem.ItemPositionHasChanged:
            for edge in self.edges:
                edge.adjust()
        return super().itemChange(change, value)
        
    def hoverEnterEvent(self, event):
        self.setBrush(QBrush(self.hover_color))
        self.setScale(1.5)
        super().hoverEnterEvent(event)
        
    def hoverLeaveEvent(self, event):
        self.setBrush(QBrush(self.default_color))
        self.setScale(1.0)
        super().hoverLeaveEvent(event)


class NeuralEdge(QGraphicsLineItem):
    def __init__(self, source_node, target_node):
        super().__init__()
        self.source = source_node
        self.target = target_node
        self.source.add_edge(self)
        self.target.add_edge(self)
        self.setZValue(1)
        self.setPen(QPen(QColor(100, 100, 100, 80), 1))
        self.adjust()

    def adjust(self):
        self.setLine(self.source.scenePos().x(), self.source.scenePos().y(),
                     self.target.scenePos().x(), self.target.scenePos().y())


class NeuralGraphWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(0, 0, 0, 0)
        
        self.scene = QGraphicsScene(self)
        self.scene.setBackgroundBrush(QBrush(QColor(0, 0, 0)))
        
        self.view = QGraphicsView(self.scene)
        self.view.setRenderHint(QPainter.Antialiasing)
        self.view.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.view.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.view.setDragMode(QGraphicsView.RubberBandDrag)
        self.view.setStyleSheet("border: none; background: #000000;")
        
        self.layout.addWidget(self.view)
        
        # Graph data
        self.nodes = []
        self.edges = []
        
        # Physics Engine constants
        self.repulsion_constant = 4000.0
        self.spring_constant = 0.03
        self.spring_length = 80.0
        self.damping = 0.85
        
        self.timer = QTimer(self)
        self.timer.timeout.connect(self._apply_physics)
        self.is_simulating = False
        
    def load_data(self, graph_data):
        """
        Loads graph data and starts the simulation.
        graph_data: {'nodes': [{'id': 'CVE-123', 'label': 'WordPress'}, ...], 'edges': [('CVE-123', 'CVE-456'), ...]}
        """
        self.scene.clear()
        self.nodes.clear()
        self.edges.clear()
        
        node_map = {}
        
        # Optimization: Only load up to 150 nodes to maintain 60FPS UI
        max_nodes = 150
        nodes_to_render = graph_data.get('nodes', [])[:max_nodes]
        allowed_ids = {n['id'] for n in nodes_to_render}
        
        # Create Nodes
        for n_data in nodes_to_render:
            node = NeuralNode(n_data['id'], n_data.get('label', ''))
            # Random initial cluster
            node.setPos(random.uniform(-100, 100), random.uniform(-100, 100))
            self.scene.addItem(node)
            self.nodes.append(node)
            node_map[n_data['id']] = node
            
        # Create Edges
        for source_id, target_id in graph_data.get('edges', []):
            if source_id in allowed_ids and target_id in allowed_ids:
                source = node_map[source_id]
                target = node_map[target_id]
                edge = NeuralEdge(source, target)
                self.scene.addItem(edge)
                self.edges.append(edge)
                
        # Start physics
        self.is_simulating = True
        self.timer.start(16) # ~60fps
        
    def _apply_physics(self):
        if not self.is_simulating:
            return
            
        total_movement = 0.0
        
        # 1. Repulsion (Coulomb)
        for i, n1 in enumerate(self.nodes):
            for j in range(i + 1, len(self.nodes)):
                n2 = self.nodes[j]
                dx = n1.scenePos().x() - n2.scenePos().x()
                dy = n1.scenePos().y() - n2.scenePos().y()
                dist_sq = dx*dx + dy*dy
                if dist_sq < 0.1:
                    dist_sq = 0.1
                    dx = random.uniform(-1, 1)
                    dy = random.uniform(-1, 1)
                
                # Optimized repulsion distance limit
                if dist_sq < 40000: # ~200px
                    dist = math.sqrt(dist_sq)
                    force = self.repulsion_constant / dist_sq
                    fx = (dx / dist) * force
                    fy = (dy / dist) * force
                    
                    n1.vx += fx
                    n1.vy += fy
                    n2.vx -= fx
                    n2.vy -= fy

        # 2. Attraction (Spring)
        for edge in self.edges:
            n1 = edge.source
            n2 = edge.target
            dx = n2.scenePos().x() - n1.scenePos().x()
            dy = n2.scenePos().y() - n1.scenePos().y()
            dist = math.sqrt(dx*dx + dy*dy)
            if dist < 0.1:
                dist = 0.1
                
            force = (dist - self.spring_length) * self.spring_constant
            fx = (dx / dist) * force
            fy = (dy / dist) * force
            
            n1.vx += fx
            n1.vy += fy
            n2.vx -= fx
            n2.vy -= fy
            
        # 3. Center Gravity (pulls graph to center)
        for n in self.nodes:
            dx = -n.scenePos().x()
            dy = -n.scenePos().y()
            dist = math.sqrt(dx*dx + dy*dy)
            if dist > 0:
                n.vx += (dx / dist) * (dist * 0.001)
                n.vy += (dy / dist) * (dist * 0.001)
                
        # 4. Apply Velocity and Damping
        for n in self.nodes:
            n.vx *= self.damping
            n.vy *= self.damping
            
            movement = math.sqrt(n.vx*n.vx + n.vy*n.vy)
            total_movement += movement
            
            new_x = n.scenePos().x() + n.vx
            new_y = n.scenePos().y() + n.vy
            n.setPos(new_x, new_y)
            
        # Optional: Auto-stop when settled
        if total_movement < len(self.nodes) * 0.05:
            self.is_simulating = False
            self.timer.stop()
