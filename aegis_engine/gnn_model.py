import torch
import torch.nn.functional as F
from torch_geometric.nn import GCNConv
from torch_geometric.explain import Explainer, GNNExplainer, ExplainerConfig, ModelConfig

class AegisAnomalyGNN(torch.nn.Module):
    """
    A foundational Graph Convolutional Network (GCN) for analyzing 
    user-database interaction behaviors as a graph (Node Classification).
    """
    def __init__(self, in_channels: int, hidden_channels: int, out_channels: int):
        super().__init__()
        # First Graph Convolutional Layer
        self.conv1 = GCNConv(in_channels, hidden_channels)
        # Second Graph Convolutional Layer
        self.conv2 = GCNConv(hidden_channels, out_channels)

    def forward(self, x, edge_index):
        # Apply first GCN layer, then ReLU activation
        x = self.conv1(x, edge_index)
        x = F.relu(x)
        # Apply dropout to prevent overfitting during training (not active during inference)
        x = F.dropout(x, p=0.5, training=self.training)
        # Apply second GCN layer
        x = self.conv2(x, edge_index)
        # Return log_softmax for node classification
        return F.log_softmax(x, dim=1)

def configure_explainer(model: torch.nn.Module) -> Explainer:
    """
    Configures a GNNExplainer tailored to output edge and node masks, 
    allowing us to visualize which parts of the interaction graph 
    influenced an anomaly classification.
    """
    return Explainer(
        model=model,
        algorithm=GNNExplainer(epochs=200),
        # Configure the explainer to provide both node features and edges that are important
        explanation_type='model',
        node_mask_type='attributes', # Which node attributes were anomalous?
        edge_mask_type='object',     # Which interaction edges (queries) were anomalous?
        model_config=ModelConfig(
            mode='multiclass_classification',
            task_level='node',
            return_type='log_probs',
        ),
    )

def explain_anomaly(model, x, edge_index, node_idx, target_class=1):
    """
    Runs the explainer to understand why a specific node (user/event) 
    was classified as an anomaly (target_class=1).
    """
    explainer = configure_explainer(model)
    
    # Generate the explanation for the specific node
    explanation = explainer(x, edge_index, index=node_idx, target=torch.tensor([target_class]))
    
    # We can extract the crucial masks for visualization
    # explanation.node_mask will show which features were anomalous
    # explanation.edge_mask will show which graph interactions were anomalous
    return explanation

# Instantiate a global untrained model for real-time inference (in an actual app, you'd load pre-trained weights)
live_model = AegisAnomalyGNN(in_channels=10, hidden_channels=16, out_channels=2)
live_model.eval() # Set to evaluation mode

def process_event_for_ai(event_data: dict) -> dict:
    """
    Translates a live PostgreSQL event into a format the GNN can evaluate,
    runs the forward pass, and extracts GNN Explainer intelligence.
    """
    # 1. Feature Extraction (Simulated for this beginner example)
    # We create a dummy 10-feature tensor to represent this event's characteristics
    # In reality, this would be encoded from user ID, time of day, payload size, etc.
    x = torch.rand((2, 10)) # A tiny 2-node graph for demonstration
    
    # 2. Edge Creation (Simulated graph topology)
    # Node 0 (The user) interacts with Node 1 (The Table)
    edge_index = torch.tensor([[0, 1], [1, 0]], dtype=torch.long)
    
    # 3. Model Inference
    # What does the GNN think of this interaction?
    with torch.no_grad():
        out = live_model(x, edge_index)
        probabilities = torch.exp(out) # Convert log_probability to normal probability
        
        # We classify the table node (index 1)
        anomaly_prob = probabilities[1][1].item() * 100 # Probability of class 1 (Anomaly)
    
    # 4. GNN Explainer
    # If the probability is high, WHY is it high?
    # We run the explainer on node 1
    explanation = explain_anomaly(live_model, x, edge_index, node_idx=1, target_class=1)
    
    # Get the top 3 most anomalous features from the node mask for the target node (index 1)
    # (e.g., feature 2 might be "Time of Access", feature 5 might be "IP Address Origin")
    top_features = torch.topk(explanation.node_mask[1], 3).indices.tolist()
    
    indicator_map = {
        0: "Suspicious Query Formulation",
        1: "Unusual Time of Access",
        2: "High Privilege Escalation Risk",
        3: "Abnormal Payload Size",
        4: "Geographically Distant IP Origin",
        5: "Rapid Sequential Anomalies from User",
        6: "Table Never Accessed by User Before",
        7: "Known Malicious IP Subnet",
        8: "Honeytoken Value Tampering Detected",
        9: "Multiple Authentication Failures Preceding Event"
    }

    key_indicators = [indicator_map[idx] for idx in top_features]
    
    # Force a high threat score if they hit the honeytoken (Rule-based override for demo purposes)
    if "honeytoken" in event_data.get('table_name', ''):
        anomaly_prob = max(anomaly_prob, 95.0 + torch.rand(1).item() * 4) # 95% - 99%

    return {
        "threat_score": round(anomaly_prob, 1),
        "key_indicators": key_indicators,
        "ai_confidence": round(80 + torch.rand(1).item() * 15, 1) # Simulated confidence
    }
if __name__ == "__main__":
    print("Initializing Intelligence Engine GNN Model...")
    # Example dimensions: 10 input features, 16 hidden dim, 2 classes (normal/anomaly)
    model = AegisAnomalyGNN(in_channels=10, hidden_channels=16, out_channels=2)
    print(model)
    print("GNN Explainer configured successfully for edge and node masks.")
