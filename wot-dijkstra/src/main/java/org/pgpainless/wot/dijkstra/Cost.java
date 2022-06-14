package org.pgpainless.wot.dijkstra;

public class Cost {

    public static class SimpleCost extends Cost {

        private final double weight;

        public SimpleCost(double weight) {
            this.weight = weight;
        }

        public double getWeight() {
            return weight;
        }

        @Override
        public String toString() {
            return Double.toString(getWeight());
        }
    }

    public static class TrustCost extends Cost {

        private final int depth;
        private final int amount;
        private final String regex;

        public TrustCost(int depth, int amount, String regex) {
            this.depth = depth;
            this.amount = amount;
            this.regex = regex;
        }

        public int getDepth() {
            return depth;
        }

        public int getAmount() {
            return amount;
        }

        public String getRegex() {
            return regex;
        }

        @Override
        public String toString() {
            return "d=" +getDepth() + ",a=" + getAmount() + (regex == null ? "" : ",r=" + getRegex());
        }
    }
}
