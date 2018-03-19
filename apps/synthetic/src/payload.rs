use std::convert::From;

use bincode;
use Packet;

pub struct Payload {
    pub work_iterations: u64,
    pub index: u64,
}

pub fn parse_response(buf: &[u8]) -> Result<usize, ()> {
    match bincode::deserialize::<Payload>(buf) {
        Ok(payload) => Ok(payload.index as usize),
        Err(_) => Err(()),
    }
}

pub fn create_request(i: usize, p: &mut Packet, buf: &mut Vec<u8>) {
    return bincode::serialize_into(
        buf,
        &Payload {
            work_iterations: p.work_iterations,
            index: i as u64,
        },
        bincode::Infinite,
    ).unwrap();
}

#[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
const _IMPL_SERIALIZE_FOR_Payload: () = {
    extern crate serde as _serde;
    #[automatically_derived]
    impl _serde::Serialize for Payload {
        fn serialize<__S>(&self, __serializer: __S) -> _serde::export::Result<__S::Ok, __S::Error>
        where
            __S: _serde::Serializer,
        {
            let mut __serde_state =
                match _serde::Serializer::serialize_struct(__serializer, "Payload", 0 + 1 + 1) {
                    Result::Ok(val) => val,
                    Result::Err(err) => return Result::Err(From::from(err)),
                };
            match _serde::ser::SerializeStruct::serialize_field(
                &mut __serde_state,
                "work_iterations",
                &self.work_iterations,
            ) {
                Result::Ok(val) => val,
                Result::Err(err) => return Result::Err(From::from(err)),
            };
            match _serde::ser::SerializeStruct::serialize_field(
                &mut __serde_state,
                "index",
                &self.index,
            ) {
                Result::Ok(val) => val,
                Result::Err(err) => return Result::Err(From::from(err)),
            };
            _serde::ser::SerializeStruct::end(__serde_state)
        }
    }
};
#[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
const _IMPL_DESERIALIZE_FOR_Payload: () = {
    extern crate serde as _serde;
    #[automatically_derived]
    impl<'de> _serde::Deserialize<'de> for Payload {
        fn deserialize<__D>(__deserializer: __D) -> _serde::export::Result<Self, __D::Error>
        where
            __D: _serde::Deserializer<'de>,
        {
            #[allow(non_camel_case_types)]
            enum __Field {
                __field0,
                __field1,
                __ignore,
            }
            struct __FieldVisitor;
            impl<'de> _serde::de::Visitor<'de> for __FieldVisitor {
                type Value = __Field;
                fn expecting(
                    &self,
                    formatter: &mut _serde::export::Formatter,
                ) -> _serde::export::fmt::Result {
                    _serde::export::Formatter::write_str(formatter, "field identifier")
                }
                fn visit_u64<__E>(self, __value: u64) -> _serde::export::Result<Self::Value, __E>
                where
                    __E: _serde::de::Error,
                {
                    match __value {
                        0u64 => _serde::export::Ok(__Field::__field0),
                        1u64 => _serde::export::Ok(__Field::__field1),
                        _ => _serde::export::Err(_serde::de::Error::invalid_value(
                            _serde::de::Unexpected::Unsigned(__value),
                            &"field index 0 <= i < 2",
                        )),
                    }
                }
                fn visit_str<__E>(self, __value: &str) -> _serde::export::Result<Self::Value, __E>
                where
                    __E: _serde::de::Error,
                {
                    match __value {
                        "work_iterations" => _serde::export::Ok(__Field::__field0),
                        "index" => _serde::export::Ok(__Field::__field1),
                        _ => _serde::export::Ok(__Field::__ignore),
                    }
                }
                fn visit_bytes<__E>(
                    self,
                    __value: &[u8],
                ) -> _serde::export::Result<Self::Value, __E>
                where
                    __E: _serde::de::Error,
                {
                    match __value {
                        b"work_iterations" => _serde::export::Ok(__Field::__field0),
                        b"index" => _serde::export::Ok(__Field::__field1),
                        _ => _serde::export::Ok(__Field::__ignore),
                    }
                }
            }
            impl<'de> _serde::Deserialize<'de> for __Field {
                #[inline]
                fn deserialize<__D>(__deserializer: __D) -> _serde::export::Result<Self, __D::Error>
                where
                    __D: _serde::Deserializer<'de>,
                {
                    _serde::Deserializer::deserialize_identifier(__deserializer, __FieldVisitor)
                }
            }
            struct __Visitor<'de> {
                marker: _serde::export::PhantomData<Payload>,
                lifetime: _serde::export::PhantomData<&'de ()>,
            }
            impl<'de> _serde::de::Visitor<'de> for __Visitor<'de> {
                type Value = Payload;
                fn expecting(
                    &self,
                    formatter: &mut _serde::export::Formatter,
                ) -> _serde::export::fmt::Result {
                    _serde::export::Formatter::write_str(formatter, "struct Payload")
                }
                #[inline]
                fn visit_seq<__A>(
                    self,
                    mut __seq: __A,
                ) -> _serde::export::Result<Self::Value, __A::Error>
                where
                    __A: _serde::de::SeqAccess<'de>,
                {
                    let __field0 =
                        match match _serde::de::SeqAccess::next_element::<u64>(&mut __seq) {
                            Result::Ok(val) => val,
                            Result::Err(err) => return Result::Err(From::from(err)),
                        } {
                            _serde::export::Some(__value) => __value,
                            _serde::export::None => {
                                return _serde::export::Err(_serde::de::Error::invalid_length(
                                    0usize,
                                    &"tuple of 2 elements",
                                ));
                            }
                        };
                    let __field1 =
                        match match _serde::de::SeqAccess::next_element::<u64>(&mut __seq) {
                            Result::Ok(val) => val,
                            Result::Err(err) => return Result::Err(From::from(err)),
                        } {
                            _serde::export::Some(__value) => __value,
                            _serde::export::None => {
                                return _serde::export::Err(_serde::de::Error::invalid_length(
                                    1usize,
                                    &"tuple of 2 elements",
                                ));
                            }
                        };
                    _serde::export::Ok(Payload {
                        work_iterations: __field0,
                        index: __field1,
                    })
                }
                #[inline]
                fn visit_map<__A>(
                    self,
                    mut __map: __A,
                ) -> _serde::export::Result<Self::Value, __A::Error>
                where
                    __A: _serde::de::MapAccess<'de>,
                {
                    let mut __field0: _serde::export::Option<u64> = _serde::export::None;
                    let mut __field1: _serde::export::Option<u64> = _serde::export::None;
                    while let _serde::export::Some(__key) =
                        match _serde::de::MapAccess::next_key::<__Field>(&mut __map) {
                            Result::Ok(val) => val,
                            Result::Err(err) => return Result::Err(From::from(err)),
                        } {
                        match __key {
                            __Field::__field0 => {
                                if _serde::export::Option::is_some(&__field0) {
                                    return _serde::export::Err(
                                        <__A::Error as _serde::de::Error>::duplicate_field(
                                            "work_iterations",
                                        ),
                                    );
                                }
                                __field0 = _serde::export::Some(
                                    match _serde::de::MapAccess::next_value::<u64>(&mut __map) {
                                        Result::Ok(val) => val,
                                        Result::Err(err) => return Result::Err(From::from(err)),
                                    },
                                );
                            }
                            __Field::__field1 => {
                                if _serde::export::Option::is_some(&__field1) {
                                    return _serde::export::Err(
                                        <__A::Error as _serde::de::Error>::duplicate_field("index"),
                                    );
                                }
                                __field1 = _serde::export::Some(
                                    match _serde::de::MapAccess::next_value::<u64>(&mut __map) {
                                        Result::Ok(val) => val,
                                        Result::Err(err) => return Result::Err(From::from(err)),
                                    },
                                );
                            }
                            _ => {
                                let _ = match _serde::de::MapAccess::next_value::<
                                    _serde::de::IgnoredAny,
                                >(&mut __map)
                                {
                                    Result::Ok(val) => val,
                                    Result::Err(err) => return Result::Err(From::from(err)),
                                };
                            }
                        }
                    }
                    let __field0 = match __field0 {
                        _serde::export::Some(__field0) => __field0,
                        _serde::export::None => {
                            match _serde::private::de::missing_field("work_iterations") {
                                Result::Ok(val) => val,
                                Result::Err(err) => return Result::Err(From::from(err)),
                            }
                        }
                    };
                    let __field1 = match __field1 {
                        _serde::export::Some(__field1) => __field1,
                        _serde::export::None => match _serde::private::de::missing_field("index") {
                            Result::Ok(val) => val,
                            Result::Err(err) => return Result::Err(From::from(err)),
                        },
                    };
                    _serde::export::Ok(Payload {
                        work_iterations: __field0,
                        index: __field1,
                    })
                }
            }
            const FIELDS: &'static [&'static str] = &["work_iterations", "index"];
            _serde::Deserializer::deserialize_struct(
                __deserializer,
                "Payload",
                FIELDS,
                __Visitor {
                    marker: _serde::export::PhantomData::<Payload>,
                    lifetime: _serde::export::PhantomData,
                },
            )
        }
    }
};
