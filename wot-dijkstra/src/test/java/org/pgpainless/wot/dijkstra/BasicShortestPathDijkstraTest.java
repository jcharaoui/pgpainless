package org.pgpainless.wot.dijkstra;

import java.util.Arrays;

import org.junit.jupiter.api.Test;

public class BasicShortestPathDijkstraTest {

    @Test
    public void test() {
        Node<String> root = new Node<>("Root");
        Node<String> alice = new Node<>("Alice");
        Node<String> alexandra = new Node<>("Alexandra");
        Node<String> karlos = new Node<>("Karlos");
        Node<String> pablo = new Node<>("Pablo");
        Node<String> malte = new Node<>("Malte");
        Node<String> sven = new Node<>("Sven");

        Graph<String, Node<String>, SimpleEdge<String>, Cost.SimpleCost> graph = new Graph<>(
                Arrays.asList(root, alice, alexandra, karlos, pablo, malte, sven),
                Arrays.asList(
                        new SimpleEdge<>(root, alice, 2d),
                        new SimpleEdge<>(alice, alexandra, 3d),
                        new SimpleEdge<>(root, karlos, 1d),
                        new SimpleEdge<>(karlos, alexandra, 1d),
                        new SimpleEdge<>(karlos, malte, 2d),
                        new SimpleEdge<>(malte, sven, 4d)
                ));

        ShortestPathDijkstra<String> dijkstra = new ShortestPathDijkstra<>(graph, root);
        System.out.println(dijkstra.findPath(sven));
        System.out.println(dijkstra.findPath(karlos));
        System.out.println(dijkstra.findPath(alexandra));

        dijkstra = new ShortestPathDijkstra<>(graph, karlos);
        System.out.println(dijkstra.findPath(sven));
    }
}
