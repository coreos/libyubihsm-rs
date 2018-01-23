error_chain! {
    foreign_links {
        Nul(::std::ffi::NulError);
    }
}
