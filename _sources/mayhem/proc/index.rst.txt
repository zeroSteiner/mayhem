:mod:`proc`
===========

.. module:: proc
   :synopsis: mayhem base classes

This module contains base classes for OS specific objects to inherit from.

Modules
-------

.. toctree::
   :maxdepth: 2
   :titlesonly:

   linux.rst
   native.rst
   windows.rst

Classes
-------

.. autoclass:: mayhem.proc.Hook
   :members:
   :special-members: __init__
   :undoc-members:

.. autoclass:: mayhem.proc.MemoryRegion
   :members:
   :special-members: __init__
   :undoc-members:

.. autoclass:: mayhem.proc.ProcessBase
   :members:
   :special-members: __init__
   :undoc-members:

Exceptions
----------

.. autoexception:: mayhem.proc.ProcessError
   :members:
   :undoc-members:
