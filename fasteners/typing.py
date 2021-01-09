"""
Literal type is only available in python 3.8. We vendor in it's backport from
https://github.com/python/typing/blob/master/typing_extensions/src_py3/typing_extensions.py
"""
import sys
import typing

if hasattr(typing, 'Literal'):
    Literal = typing.Literal
elif sys.version_info[:2] >= (3, 7):
    class _LiteralForm(typing._SpecialForm, _root=True):

        def __repr__(self):
            return 'typing_extensions.' + self._name

        def __getitem__(self, parameters):
            return typing._GenericAlias(self, parameters)

    Literal = _LiteralForm('Literal',
                           doc="""A type that can be used to indicate to type checkers
                           that the corresponding value has a value literally equivalent
                           to the provided parameter. For example:
                               var: Literal[4] = 4
                           The type checker understands that 'var' is literally equal to
                           the value 4 and no other value.
                           Literal[...] cannot be subclassed. There is no runtime
                           checking verifying that the parameter is actually a value
                           instead of a type.""")
elif hasattr(typing, '_FinalTypingBase'):
    class _Literal(typing._FinalTypingBase, _root=True):
        """A type that can be used to indicate to type checkers that the
        corresponding value has a value literally equivalent to the
        provided parameter. For example:
            var: Literal[4] = 4
        The type checker understands that 'var' is literally equal to the
        value 4 and no other value.
        Literal[...] cannot be subclassed. There is no runtime checking
        verifying that the parameter is actually a value instead of a type.
        """

        __slots__ = ('__values__',)

        def __init__(self, values=None, **kwds):
            self.__values__ = values

        def __getitem__(self, values):
            cls = type(self)
            if self.__values__ is None:
                if not isinstance(values, tuple):
                    values = (values,)
                return cls(values, _root=True)
            raise TypeError('{} cannot be further subscripted'
                            .format(cls.__name__[1:]))

        def _eval_type(self, globalns, localns):
            return self

        def __repr__(self):
            r = super().__repr__()
            if self.__values__ is not None:
                r += '[{}]'.format(', '.join(map(typing._type_repr, self.__values__)))
            return r

        def __hash__(self):
            return hash((type(self).__name__, self.__values__))

        def __eq__(self, other):
            if not isinstance(other, _Literal):
                return NotImplemented
            if self.__values__ is not None:
                return self.__values__ == other.__values__
            return self is other

    Literal = _Literal(_root=True)
else:
    class _LiteralMeta(typing.TypingMeta):
        """Metaclass for Literal"""

        def __new__(cls, name, bases, namespace, values=None, _root=False):
            self = super().__new__(cls, name, bases, namespace, _root=_root)
            if values is not None:
                self.__values__ = values
            return self

        def __instancecheck__(self, obj):
            raise TypeError("Literal cannot be used with isinstance().")

        def __subclasscheck__(self, cls):
            raise TypeError("Literal cannot be used with issubclass().")

        def __getitem__(self, item):
            cls = type(self)
            if self.__values__ is not None:
                raise TypeError('{} cannot be further subscripted'
                                .format(cls.__name__[1:]))

            if not isinstance(item, tuple):
                item = (item,)
            return cls(self.__name__, self.__bases__,
                       dict(self.__dict__), values=item, _root=True)

        def _eval_type(self, globalns, localns):
            return self

        def __repr__(self):
            r = super().__repr__()
            if self.__values__ is not None:
                r += '[{}]'.format(', '.join(map(typing._type_repr, self.__values__)))
            return r

        def __hash__(self):
            return hash((type(self).__name__, self.__values__))

        def __eq__(self, other):
            if not isinstance(other, Literal):
                return NotImplemented
            if self.__values__ is not None:
                return self.__values__ == other.__values__
            return self is other

    class Literal(typing.Final, metaclass=_LiteralMeta, _root=True):
        """A type that can be used to indicate to type checkers that the
        corresponding value has a value literally equivalent to the
        provided parameter. For example:
            var: Literal[4] = 4
        The type checker understands that 'var' is literally equal to the
        value 4 and no other value.
        Literal[...] cannot be subclassed. There is no runtime checking
        verifying that the parameter is actually a value instead of a type.
        """

        __values__ = None
