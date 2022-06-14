package org.pgpainless.wot.dijkstra;

public abstract class Dijkstra<T, E extends Edge<T, C>, C extends Cost> {

    public abstract Path<T, Node<T>, C, E> findPath(Node<T> to);
}
