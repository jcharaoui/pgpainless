package org.pgpainless.wot.dijkstra;

public class WotDijkstra<T> extends Dijkstra<T, TrustEdge<T>, Cost.TrustCost> {

    @Override
    public Path<T, Node<T>, Cost.TrustCost, TrustEdge<T>> findPath(Node<T> to) {
        return null;
    }
}

