use aegis_authority::{ActionSetV1, ActionV1};

fn set(bits: u8) -> ActionSetV1 {
    let mut result = ActionSetV1::bottom();
    for (index, action) in [
        ActionV1::Observe,
        ActionV1::Submit,
        ActionV1::Modify,
        ActionV1::Execute,
        ActionV1::Delegate,
        ActionV1::Administer,
    ]
    .into_iter()
    .enumerate()
    {
        if bits & (1 << index) != 0 {
            result = result.join(ActionSetV1::singleton(action));
        }
    }
    result
}

#[test]
fn exhaustive_six_action_algebra_is_a_distributive_bounded_lattice() {
    let sets: Vec<_> = (0..64).map(set).collect();
    for &a in &sets {
        assert_eq!(a.meet(ActionSetV1::top()), a);
        assert_eq!(a.join(ActionSetV1::bottom()), a);
        assert_eq!(a.meet(a), a);
        assert_eq!(a.join(a), a);
        for &b in &sets {
            assert_eq!(a.meet(b), b.meet(a));
            assert_eq!(a.join(b), b.join(a));
            assert_eq!(a.meet(a.join(b)), a);
            assert_eq!(a.join(a.meet(b)), a);
            assert_eq!(a.is_subset_of(b), a.meet(b) == a);
            for &c in &sets {
                assert_eq!(a.meet(b).meet(c), a.meet(b.meet(c)));
                assert_eq!(a.join(b).join(c), a.join(b.join(c)));
                assert_eq!(a.meet(b.join(c)), a.meet(b).join(a.meet(c)));
                assert_eq!(a.join(b.meet(c)), a.join(b).meet(a.join(c)));
            }
        }
    }
}
