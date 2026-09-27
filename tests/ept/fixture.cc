#include "fixture.hpp"

namespace ept_test {
void EptTest::SetUp() {
    platform().Reset();
    original.fill(0);
    original[1] = 7;
    original[0x11] = 3;
    cpu = std::make_unique<hv::vcpu_ept_data>();
    ASSERT_TRUE(hv::prepare_ept(*cpu));
}
void EptTest::TearDown() {
    cpu.reset();
    platform().Reset();
}
blook::hook_spec EptTest::Hook(uint64_t id, uint64_t pfn, uint64_t target) {
    blook::hook_spec spec{};
    spec.id = id;
    spec.pfn = pfn;
    spec.target = target;
    spec.address_space = 100;
    spec.identity_address = 0x200000;
    spec.original = original.data();
    spec.length = 1;
    spec.patch[0] = 42;
    spec.domain = blook::hook_domain::user;
    return spec;
}
uint32_t EptTest::ShadowPfn(size_t slot) const {
    return cpu->groups[cpu->hooks[slot].group].shadow_pfn;
}
}  // namespace ept_test
