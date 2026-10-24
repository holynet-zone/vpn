use crate::land::LAND;
use crate::{GlobeArc, GlobeDot};
use crate::{Lang, domain};
use slint::{ModelRc, SharedString, VecModel};
use std::fmt::Write;
use std::sync::OnceLock;

pub const W: f32 = 300.0;
pub const H: f32 = 280.0;
const CX: f32 = W / 2.0;
const CY: f32 = H / 2.0;

pub fn radius(zoom: f32) -> f32 {
    (H.min(W) / 2.0) * 0.92 * zoom
}

pub type Mat3 = [[f32; 3]; 3];

#[inline]
fn dot3(a: &[f32; 3], v: (f32, f32, f32)) -> f32 {
    a[0] * v.0 + a[1] * v.1 + a[2] * v.2
}

pub fn mat_mul(a: &Mat3, b: &Mat3) -> Mat3 {
    let mut o = [[0.0f32; 3]; 3];
    for i in 0..3 {
        for j in 0..3 {
            o[i][j] = a[i][0] * b[0][j] + a[i][1] * b[1][j] + a[i][2] * b[2][j];
        }
    }
    o
}

// Ориентация глобуса: строки — экранный базис (вправо, вверх, к зрителю) в
// мировых координатах. Экран: x = CX + r·(right·v), y = CY − r·(up·v);
// видимость: depth·v ≥ 0.
pub fn orient_from_angles(lon0: f32, lat0: f32, roll: f32) -> Mat3 {
    let (slon, clon) = lon0.to_radians().sin_cos();
    let (slat, clat) = lat0.to_radians().sin_cos();
    let right = [-slon, clon, 0.0];
    let up = [-slat * clon, -slat * slon, clat];
    let depth = [clat * clon, clat * slon, slat];
    let (sr, cr) = roll.to_radians().sin_cos();
    [
        [
            cr * right[0] + sr * up[0],
            cr * right[1] + sr * up[1],
            cr * right[2] + sr * up[2],
        ],
        [
            -sr * right[0] + cr * up[0],
            -sr * right[1] + cr * up[1],
            -sr * right[2] + cr * up[2],
        ],
        depth,
    ]
}

// Поворот на theta_deg вокруг единичной оси (ax, ay, az), заданной в экранном
// базисе (вправо, вверх, к зрителю) — формула Родрига.
pub fn rot_about(ax: f32, ay: f32, az: f32, theta_deg: f32) -> Mat3 {
    let (s, c) = theta_deg.to_radians().sin_cos();
    let t = 1.0 - c;
    [
        [c + t * ax * ax, t * ax * ay - s * az, t * ax * az + s * ay],
        [t * ax * ay + s * az, c + t * ay * ay, t * ay * az - s * ax],
        [t * ax * az - s * ay, t * ay * az + s * ax, c + t * az * az],
    ]
}

fn norm3(v: [f32; 3]) -> [f32; 3] {
    let l = (v[0] * v[0] + v[1] * v[1] + v[2] * v[2]).sqrt();
    if l > 1e-6 {
        [v[0] / l, v[1] / l, v[2] / l]
    } else {
        v
    }
}

fn cross3(a: [f32; 3], b: [f32; 3]) -> [f32; 3] {
    [
        a[1] * b[2] - a[2] * b[1],
        a[2] * b[0] - a[0] * b[2],
        a[0] * b[1] - a[1] * b[0],
    ]
}

// Грам-Шмидт: держим матрицу ортонормированной, чтобы за много поворотов не
// накапливался дрейф.
pub fn orthonormalize(m: &Mat3) -> Mat3 {
    let depth = norm3(m[2]);
    let d = m[1][0] * depth[0] + m[1][1] * depth[1] + m[1][2] * depth[2];
    let up = norm3([
        m[1][0] - d * depth[0],
        m[1][1] - d * depth[1],
        m[1][2] - d * depth[2],
    ]);
    let right = cross3(up, depth);
    [right, up, depth]
}

struct Rot {
    m: Mat3,
    r: f32,
}

impl Rot {
    fn new(m: &Mat3, r: f32) -> Self {
        Self { m: *m, r }
    }

    #[inline]
    fn proj(&self, v: (f32, f32, f32)) -> (f32, f32, bool) {
        let rx = dot3(&self.m[0], v);
        let uy = dot3(&self.m[1], v);
        let dz = dot3(&self.m[2], v);
        (CX + self.r * rx, CY - self.r * uy, dz >= 0.0)
    }
}

fn latlon_vec(lon: f32, lat: f32) -> (f32, f32, f32) {
    let lonr = lon.to_radians();
    let latr = lat.to_radians();
    (latr.cos() * lonr.cos(), latr.cos() * lonr.sin(), latr.sin())
}

fn polyline_vec(vecs: &[(f32, f32, f32)], rot: &Rot, out: &mut String) {
    let mut pen = false;
    for &v in vecs {
        let (x, y, vis) = rot.proj(v);
        if vis {
            let _ = if pen {
                write!(out, "L {:.1} {:.1} ", x, y)
            } else {
                pen = true;
                write!(out, "M {:.1} {:.1} ", x, y)
            };
        } else {
            pen = false;
        }
    }
}

fn land_vecs() -> &'static Vec<Vec<(f32, f32, f32)>> {
    static V: OnceLock<Vec<Vec<(f32, f32, f32)>>> = OnceLock::new();
    V.get_or_init(|| {
        LAND.iter()
            .map(|ring| {
                ring.iter()
                    .map(|&(lon, lat)| latlon_vec(lon, lat))
                    .collect()
            })
            .collect()
    })
}

fn graticule_vecs() -> &'static Vec<Vec<(f32, f32, f32)>> {
    static V: OnceLock<Vec<Vec<(f32, f32, f32)>>> = OnceLock::new();
    V.get_or_init(|| {
        let mut lines = Vec::new();
        let mut lon = -180;
        while lon < 180 {
            let mut line = Vec::new();
            let mut lat = -80;
            while lat <= 80 {
                line.push(latlon_vec(lon as f32, lat as f32));
                lat += 4;
            }
            lines.push(line);
            lon += 30;
        }
        let mut lat = -60;
        while lat <= 60 {
            let mut line = Vec::new();
            let mut lon = -180;
            while lon <= 180 {
                line.push(latlon_vec(lon as f32, lat as f32));
                lon += 4;
            }
            lines.push(line);
            lat += 30;
        }
        lines
    })
}

fn polyline(points: &[(f32, f32)], rot: &Rot) -> String {
    let mut out = String::new();
    let mut pen = false;
    for &(lon, lat) in points {
        let (x, y, vis) = rot.proj(latlon_vec(lon, lat));
        if vis {
            let _ = if pen {
                write!(out, "L {:.1} {:.1} ", x, y)
            } else {
                pen = true;
                write!(out, "M {:.1} {:.1} ", x, y)
            };
        } else {
            pen = false;
        }
    }
    out
}

fn graticule(rot: &Rot) -> String {
    let mut out = String::new();
    for line in graticule_vecs() {
        polyline_vec(line, rot, &mut out);
    }
    out
}

fn land_path(rot: &Rot) -> String {
    let mut out = String::new();
    for ring in land_vecs() {
        polyline_vec(ring, rot, &mut out);
    }
    out
}

fn slerp(a: (f32, f32), b: (f32, f32), t: f32) -> (f32, f32) {
    let (alo, ala) = (a.0.to_radians(), a.1.to_radians());
    let (blo, bla) = (b.0.to_radians(), b.1.to_radians());
    let av = (ala.cos() * alo.cos(), ala.cos() * alo.sin(), ala.sin());
    let bv = (bla.cos() * blo.cos(), bla.cos() * blo.sin(), bla.sin());
    let dot = (av.0 * bv.0 + av.1 * bv.1 + av.2 * bv.2).clamp(-1.0, 1.0);
    let omega = dot.acos();
    if omega.abs() < 1e-4 {
        return a;
    }
    let s = omega.sin();
    let s0 = ((1.0 - t) * omega).sin() / s;
    let s1 = (t * omega).sin() / s;
    let x = s0 * av.0 + s1 * bv.0;
    let y = s0 * av.1 + s1 * bv.1;
    let z = s0 * av.2 + s1 * bv.2;
    (y.atan2(x).to_degrees(), z.asin().to_degrees())
}

fn arc_path(a: (f32, f32), b: (f32, f32), rot: &Rot) -> String {
    let steps = 28;
    let mut pts = Vec::with_capacity(steps + 1);
    for i in 0..=steps {
        let t = i as f32 / steps as f32;
        pts.push(slerp(a, b, t));
    }
    polyline(&pts, rot)
}

pub struct Frame {
    pub graticule: SharedString,
    pub land: SharedString,
    pub arcs: ModelRc<GlobeArc>,
    pub dots: ModelRc<GlobeDot>,
    pub radius: f32,
}

pub fn render(
    space: &str,
    path: &[&str],
    lang: Lang,
    orient: &Mat3,
    zoom: f32,
    probing: bool,
) -> Frame {
    let r = radius(zoom);
    let rot = Rot::new(orient, r);

    let nodes = domain::globe_points(space, lang);
    let mut active = std::collections::HashSet::new();
    for w in path.windows(2) {
        active.insert((w[0].to_string(), w[1].to_string()));
        active.insert((w[1].to_string(), w[0].to_string()));
    }
    let exit = path.last().copied().unwrap_or("");
    let is_hop = |id: &str| path.contains(&id) && id != exit;

    let find = |id: &str| nodes.iter().find(|n| n.id == id).cloned();

    let mut arcs: Vec<GlobeArc> = Vec::new();
    for e in domain::globe_edges(space) {
        let (Some(a), Some(b)) = (find(&e.a), find(&e.b)) else {
            continue;
        };
        let dead = e.rtt < 0;
        let act = active.contains(&(e.a.clone(), e.b.clone()));
        let kind = if dead {
            3
        } else if act {
            1
        } else if e.stale {
            2
        } else {
            0
        };
        let dash = if dead {
            1
        } else if e.stale {
            2
        } else {
            0
        };
        arcs.push(GlobeArc {
            d: arc_path((a.lon, a.lat), (b.lon, b.lat), &rot).into(),
            kind,
            width: if act { 2.4 } else { 1.1 },
            dash,
        });
    }

    if let (Some(me), Some(first)) = (
        nodes.iter().find(|n| n.is_me).cloned(),
        path.first().and_then(|id| find(id)),
    ) {
        arcs.push(GlobeArc {
            d: arc_path((me.lon, me.lat), (first.lon, first.lat), &rot).into(),
            kind: 1,
            width: 2.0,
            dash: 2,
        });
    }

    let mut dots: Vec<GlobeDot> = Vec::new();
    for n in &nodes {
        let (x, y, vis) = rot.proj(latlon_vec(n.lon, n.lat));
        if !vis {
            continue;
        }
        let dead = n.rtt < 0 && !n.is_me;
        let is_exit = n.id == exit && !n.is_me;
        let hop = is_hop(&n.id);
        let rr = if n.is_me {
            4.5
        } else if is_exit {
            7.5
        } else if hop {
            6.0
        } else {
            4.5
        };
        let fill = if n.is_me {
            3
        } else if dead {
            0
        } else if is_exit {
            1
        } else if hop {
            2
        } else {
            0
        };
        let stroke = if n.is_me {
            3
        } else if dead {
            4
        } else if is_exit || hop {
            1
        } else if n.stale {
            2
        } else {
            1
        };
        let rtt = if n.is_me {
            String::new()
        } else if probing {
            "···".to_string()
        } else if dead {
            "—".to_string()
        } else {
            n.rtt.to_string()
        };
        dots.push(GlobeDot {
            id: n.id.clone().into(),
            x,
            y,
            r: rr,
            fill,
            stroke,
            code: n.code.clone().into(),
            rtt: rtt.into(),
            lx: x + 9.0,
            ly: y,
            is_me: n.is_me,
            is_exit,
            dead,
        });
    }

    Frame {
        graticule: graticule(&rot).into(),
        land: land_path(&rot).into(),
        arcs: ModelRc::new(VecModel::from(arcs)),
        dots: ModelRc::new(VecModel::from(dots)),
        radius: r,
    }
}

pub fn hit_test(
    space: &str,
    lang: Lang,
    orient: &Mat3,
    zoom: f32,
    tx: f32,
    ty: f32,
) -> Option<String> {
    let rot = Rot::new(orient, radius(zoom));
    let mut best: Option<(f32, String)> = None;
    for n in domain::globe_points(space, lang) {
        if n.is_me || n.rtt < 0 {
            continue;
        }
        let (x, y, vis) = rot.proj(latlon_vec(n.lon, n.lat));
        if !vis {
            continue;
        }
        let d = ((x - tx).powi(2) + (y - ty).powi(2)).sqrt();
        if d <= 16.0 && best.as_ref().map(|(bd, _)| d < *bd).unwrap_or(true) {
            best = Some((d, n.id.clone()));
        }
    }
    best.map(|(_, id)| id)
}
