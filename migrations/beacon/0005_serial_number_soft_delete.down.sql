DROP INDEX IF EXISTS ux_beacons_serial_number;

CREATE UNIQUE INDEX ux_beacons_serial_number ON beacons (serial_number);
