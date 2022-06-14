package org.pgpainless.wot.dijkstra;

public class Node<T> {

    private final T item;

    public Node(T item) {
        this.item = item;
    }

    private T getItem() {
        return item;
    }

    @Override
    public String toString() {
        return "(" + getItem().toString() + ")";
    }
}
