package org.pgpainless.wot.dijkstra;

public class SimpleEdge<T> extends Edge<T, Cost.SimpleCost> {

    public SimpleEdge(Node<T> from, Node<T> to, Double edgeWeight) {
        super(from, to, new Cost.SimpleCost(edgeWeight));
    }

    @Override
    public String toString() {
        return getFrom().toString() + " " + getCost() + "> " + getTo().toString();
    }

    @Override
    public int compareTo(Cost.SimpleCost o) {
        return Double.compare(getCost().getWeight(), o.getWeight());
    }
}
