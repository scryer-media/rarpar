//! 7-Zip's wildcard censor (`Common/Wildcard.cpp`): which archive items a
//! command line selects.

/// How a name given on the command line recurses (`-r`, `-r-`, `-r0`).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub(super) enum Recursion {
    #[default]
    None,
    All,
    WildcardOnly,
}

/// 7-Zip's `-spm` mark mode: whether a name matches files, folders or both.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub(super) enum MarkMode {
    #[default]
    FileOrDir,
    StrictFile,
    StrictFileIfWildcard,
}

/// The options a name is added with.
#[derive(Clone, Copy, Debug)]
pub(super) struct NameOption {
    pub include: bool,
    pub recursion: Recursion,
    pub wildcards: bool,
    pub mark: MarkMode,
}

impl Default for NameOption {
    fn default() -> Self {
        Self {
            include: true,
            recursion: Recursion::None,
            wildcards: true,
            mark: MarkMode::FileOrDir,
        }
    }
}

#[derive(Clone, Debug)]
struct Item {
    parts: Vec<String>,
    for_file: bool,
    for_dir: bool,
    recursive: bool,
    wildcards: bool,
}

#[derive(Clone, Debug, Default)]
struct Node {
    name: String,
    subnodes: Vec<Node>,
    include: Vec<Item>,
    exclude: Vec<Item>,
}

/// The selection made by names, `-i` and `-x`.
#[derive(Clone, Debug)]
pub(super) struct Censor {
    root: Node,
    pub case_sensitive: bool,
    pub exclude_dirs: bool,
    pub exclude_files: bool,
}

pub(super) fn has_wildcard(name: &str) -> bool {
    name.contains(['*', '?'])
}

/// Split a path into its parts on 7-Zip's separators.
pub(super) fn split_path(path: &str) -> Vec<String> {
    path.split(|c: char| c == '/' || (cfg!(windows) && c == '\\'))
        .map(str::to_owned)
        .collect()
}

fn fold(c: char, case_sensitive: bool) -> char {
    if case_sensitive {
        c
    } else {
        c.to_lowercase().next().unwrap_or(c)
    }
}

/// 7-Zip's `DoesWildcardMatchName`: `*` is any run, `?` any one character.
pub(super) fn wildcard_match(mask: &str, name: &str, case_sensitive: bool) -> bool {
    let mask: Vec<char> = mask.chars().map(|c| fold(c, case_sensitive)).collect();
    let name: Vec<char> = name.chars().map(|c| fold(c, case_sensitive)).collect();
    let (mut m, mut n) = (0usize, 0usize);
    let mut star: Option<(usize, usize)> = None;
    while n < name.len() {
        if m < mask.len() && (mask[m] == '?' || (mask[m] != '*' && mask[m] == name[n])) {
            m += 1;
            n += 1;
        } else if m < mask.len() && mask[m] == '*' {
            star = Some((m, n));
            m += 1;
        } else if let Some((sm, sn)) = star {
            m = sm + 1;
            n = sn + 1;
            star = Some((sm, sn + 1));
        } else {
            return false;
        }
    }
    while m < mask.len() && mask[m] == '*' {
        m += 1;
    }
    m == mask.len()
}

pub(super) fn names_equal(a: &str, b: &str, case_sensitive: bool) -> bool {
    if case_sensitive {
        a == b
    } else {
        a.chars()
            .map(|c| fold(c, false))
            .eq(b.chars().map(|c| fold(c, false)))
    }
}

impl Item {
    fn check(&self, path: &[String], is_file: bool, case_sensitive: bool) -> bool {
        if !is_file && !self.for_dir {
            return false;
        }
        let delta = path.len() as isize - self.parts.len() as isize;
        if delta < 0 {
            return false;
        }
        let mut start = 0isize;
        let mut finish = 0isize;
        if is_file {
            if !self.for_dir {
                if self.recursive {
                    start = delta;
                } else if delta != 0 {
                    return false;
                }
            }
            if !self.for_file && delta == 0 {
                return false;
            }
        }
        if self.recursive {
            finish = delta;
            if is_file && !self.for_file {
                finish = delta - 1;
            }
        }
        let mut d = start;
        while d <= finish {
            let offset = d as usize;
            let all = self.parts.iter().enumerate().all(|(i, part)| {
                let name = &path[i + offset];
                if self.wildcards {
                    wildcard_match(part, name, case_sensitive)
                } else {
                    names_equal(part, name, case_sensitive)
                }
            });
            if all {
                return true;
            }
            d += 1;
        }
        false
    }
}

impl Node {
    fn add_item(&mut self, include: bool, mut item: Item, case_sensitive: bool) {
        if item.parts.len() <= 1 {
            if let Some(front) = item.parts.first()
                && item.wildcards
                && !has_wildcard(front)
            {
                item.wildcards = false;
            }
            if include {
                self.include.push(item);
            } else {
                self.exclude.push(item);
            }
            return;
        }
        let front = item.parts[0].clone();
        if item.wildcards && has_wildcard(&front) {
            if include {
                self.include.push(item);
            } else {
                self.exclude.push(item);
            }
            return;
        }
        let index = match self
            .subnodes
            .iter()
            .position(|node| names_equal(&node.name, &front, case_sensitive))
        {
            Some(index) => index,
            None => {
                self.subnodes.push(Node {
                    name: front,
                    ..Node::default()
                });
                self.subnodes.len() - 1
            }
        };
        item.parts.remove(0);
        self.subnodes[index].add_item(include, item, case_sensitive);
    }

    fn check_current(&self, include: bool, path: &[String], is_file: bool, cs: bool) -> bool {
        let items = if include {
            &self.include
        } else {
            &self.exclude
        };
        items.iter().any(|item| item.check(path, is_file, cs))
    }

    /// `CCensorNode::CheckPathVect`: `Some(include)` when a rule decides.
    fn check_vect(&self, path: &[String], is_file: bool, cs: bool) -> Option<bool> {
        if self.check_current(false, path, is_file, cs) {
            return Some(false);
        }
        if path.len() > 1
            && let Some(node) = self
                .subnodes
                .iter()
                .find(|node| names_equal(&node.name, &path[0], cs))
            && let Some(decided) = node.check_vect(&path[1..], is_file, cs)
        {
            return Some(decided);
        }
        self.check_current(true, path, is_file, cs).then_some(true)
    }
}

impl Censor {
    pub fn new(case_sensitive: bool) -> Self {
        Self {
            root: Node::default(),
            case_sensitive,
            exclude_dirs: false,
            exclude_files: false,
        }
    }

    /// `AddNameToCensor` followed by `CCensor::AddItem` in absolute-path
    /// mode, which is how an extract or list command's names are kept.
    pub fn add_name(&mut self, option: &NameOption, name: &str) {
        let recursive = match option.recursion {
            Recursion::All => true,
            Recursion::WildcardOnly => has_wildcard(name),
            Recursion::None => false,
        };
        let mut parts = split_path(name);
        let mut for_file = true;
        let mut for_dir = true;
        if parts.last().is_some_and(String::is_empty) {
            for_file = false;
            parts.pop();
        } else if let Some(back) = parts.last()
            && (option.mark == MarkMode::StrictFile
                || (option.mark == MarkMode::StrictFileIfWildcard && has_wildcard(back)))
        {
            for_dir = false;
        }
        let item = Item {
            parts,
            for_file,
            for_dir,
            recursive,
            wildcards: option.wildcards,
        };
        let cs = self.case_sensitive;
        self.root.add_item(option.include, item, cs);
    }

    /// Whether the item at `path` is selected.
    pub fn selects(&self, path: &str, is_dir: bool) -> bool {
        if if is_dir {
            self.exclude_dirs
        } else {
            self.exclude_files
        } {
            return false;
        }
        let parts = split_path(path);
        self.root
            .check_vect(&parts, !is_dir, self.case_sensitive)
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn censor(names: &[&str], option: NameOption) -> Censor {
        let mut censor = Censor::new(true);
        for name in names {
            censor.add_name(&option, name);
        }
        censor
    }

    #[test]
    fn wildcards() {
        assert!(wildcard_match("*", "anything.txt", true));
        assert!(wildcard_match("*.7z", "a.b.7z", true));
        assert!(!wildcard_match("*.7z", "a.7z.001", true));
        assert!(wildcard_match("a?c*", "abcdef", true));
        assert!(!wildcard_match("A*", "abc", true));
        assert!(wildcard_match("A*", "abc", false));
        assert!(wildcard_match("*a*b", "xxaxxb", true));
        assert!(!wildcard_match("*a*b", "xxaxxbc", true));
    }

    #[test]
    fn universal_selects_everything() {
        let c = censor(&["*"], NameOption::default());
        assert!(c.selects("folder/inner/pip.txt", false));
        assert!(c.selects("folder", true));
    }

    #[test]
    fn a_folder_name_selects_its_subtree() {
        let c = censor(&["folder"], NameOption::default());
        assert!(c.selects("folder", true));
        assert!(c.selects("folder/inner/pip.txt", false));
        assert!(!c.selects("other/folder", true));
        assert!(!c.selects("meadow.bin", false));
    }

    #[test]
    fn recursion_finds_names_at_any_depth() {
        let plain = censor(&["*.txt"], NameOption::default());
        assert!(plain.selects("script.txt", false));
        assert!(!plain.selects("folder/inner/pip.txt", false));
        let recursive = censor(
            &["*.txt"],
            NameOption {
                recursion: Recursion::All,
                ..NameOption::default()
            },
        );
        assert!(recursive.selects("folder/inner/pip.txt", false));
    }

    #[test]
    fn excludes_win_over_includes() {
        let mut c = censor(&["*"], NameOption::default());
        c.add_name(
            &NameOption {
                include: false,
                recursion: Recursion::All,
                ..NameOption::default()
            },
            "*.bin",
        );
        assert!(!c.selects("meadow.bin", false));
        assert!(!c.selects("folder/exe.bin", false));
        assert!(c.selects("script.txt", false));
    }

    #[test]
    fn nested_names_build_subnodes() {
        let c = censor(&["folder/inner/pip.txt"], NameOption::default());
        assert!(c.selects("folder/inner/pip.txt", false));
        assert!(!c.selects("folder/inner", true));
        assert!(!c.selects("meadow.bin", false));
    }
}
