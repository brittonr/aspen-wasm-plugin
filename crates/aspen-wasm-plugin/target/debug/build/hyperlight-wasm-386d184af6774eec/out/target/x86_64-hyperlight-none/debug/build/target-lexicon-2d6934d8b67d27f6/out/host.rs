#[allow(unused_imports)]
use crate::Aarch64Architecture::*;
#[allow(unused_imports)]
use crate::ArmArchitecture::*;
#[allow(unused_imports)]
use crate::CustomVendor;
#[allow(unused_imports)]
use crate::Mips32Architecture::*;
#[allow(unused_imports)]
use crate::Mips64Architecture::*;
#[allow(unused_imports)]
use crate::Riscv32Architecture::*;
#[allow(unused_imports)]
use crate::Riscv64Architecture::*;
#[allow(unused_imports)]
use crate::X86_32Architecture::*;

/// The `Triple` of the current host.
pub const HOST: Triple = Triple {
    architecture: Architecture::X86_64,
    vendor: Vendor::Custom(CustomVendor::Static("hyperlight")),
    operating_system: OperatingSystem::None_,
    environment: Environment::Unknown,
    binary_format: BinaryFormat::Unknown,
};

impl Architecture {
    /// Return the architecture for the current host.
    pub const fn host() -> Self {
        Architecture::X86_64
    }
}

impl Vendor {
    /// Return the vendor for the current host.
    pub const fn host() -> Self {
        Vendor::Custom(CustomVendor::Static("hyperlight"))
    }
}

impl OperatingSystem {
    /// Return the operating system for the current host.
    pub const fn host() -> Self {
        OperatingSystem::None_
    }
}

impl Environment {
    /// Return the environment for the current host.
    pub const fn host() -> Self {
        Environment::Unknown
    }
}

impl BinaryFormat {
    /// Return the binary format for the current host.
    pub const fn host() -> Self {
        BinaryFormat::Unknown
    }
}

impl Triple {
    /// Return the triple for the current host.
    pub const fn host() -> Self {
        Self {
            architecture: Architecture::X86_64,
            vendor: Vendor::Custom(CustomVendor::Static("hyperlight")),
            operating_system: OperatingSystem::None_,
            environment: Environment::Unknown,
            binary_format: BinaryFormat::Unknown,
        }
    }
}
