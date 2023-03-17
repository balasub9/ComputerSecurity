public class Timer {
    public double startTime;

    public void startTimer() {
        this.startTime = System.nanoTime();
    }

    public double getExectionTimeIn(String unit) {
        double nanoSec = System.nanoTime() - startTime;
        switch (unit.toLowerCase()) {
            case "seconds":
                return nanoSec / 1000000000;
            case "milliseconds":
                return nanoSec / 1000000;
            case "microseconds":
                return nanoSec / 1000;
            case "nanoseconds":
            default:
                return nanoSec;
        }
    }
}
