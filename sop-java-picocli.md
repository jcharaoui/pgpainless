# SOP-Java-Picocli

`sop-java-picocli` implements a command line interface for SOP implementations.

## Backend Installation
In order to enable OpenPGP operations, you need to set an implementation of [`sop-java`](sop-java.html):
```java
// static method call prior to execution of the main method
SopCLI.setSopInstance(yourSopImpl);
```

## Usage
