/// Great-circle distance in kilometres between two decimal-degree positions.
pub fn distance(lat0: f64, lon0: f64, lat1: f64, lon1: f64) -> f64 {
    let (lat0, lon0, lat1, lon1) = (
        lat0.to_radians(),
        lon0.to_radians(),
        lat1.to_radians(),
        lon1.to_radians(),
    );
    let dlat = lat1 - lat0;
    let dlon = lon1 - lon0;
    let a = (dlat / 2.0).sin().powi(2) + lat0.cos() * lat1.cos() * (dlon / 2.0).sin().powi(2);
    6366.71 * 2.0 * a.sqrt().atan2((1.0 - a).sqrt())
}

/// Initial bearing in degrees from the first position to the second.
pub fn direction(lat0: f64, lon0: f64, lat1: f64, lon1: f64) -> f64 {
    let (lat0, lon0, lat1, lon1) = (
        lat0.to_radians(),
        lon0.to_radians(),
        lat1.to_radians(),
        lon1.to_radians(),
    );
    let dlon = lon1 - lon0;
    let bearing = (dlon.sin() * lat1.cos())
        .atan2(lat0.cos() * lat1.sin() - lat0.sin() * lat1.cos() * dlon.cos())
        .to_degrees();
    if bearing < 0.0 {
        bearing + 360.0
    } else {
        bearing
    }
}
