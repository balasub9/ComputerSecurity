public class Timer {
    public long startTime;

    public void startTimer() {
        this.startTime = System.nanoTime();
    }

    public long getExectionTimeIn(String unit) {
        long nanoSec = System.nanoTime() - startTime;
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
