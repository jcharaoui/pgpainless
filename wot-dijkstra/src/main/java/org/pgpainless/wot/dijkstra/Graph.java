package org.pgpainless.wot.dijkstra;

import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class Graph {

    // Dijkstra

    // Set of initially unvisited nodes
    private final Set<Node> unvisited = new HashSet<>();
    // Initial node - trust-root in our case
    private final Node root;


    // WOT
    // KeyIDs to nodes
    private final Map<Long, Node> nodesByKeyIds = new HashMap<>();

    public Graph(Node root, Collection<Node> nodes) {
        this.root = root;
        this.unvisited.addAll(nodes);
    }

    public
}
