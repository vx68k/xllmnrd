Internals of Xenium LLMNR Responder
===================================

Interface managers
------------------

.. cpp:namespace:: xllmnrd

.. cpp:class:: interface_manager

.. cpp:function:: interface_manager::interface_manager()

   [protected]
   Constructs an interface manager object.

.. cpp:function:: interface_manager::interface_manager(const interface_manager &) = delete

   The copy constructor is deleted.

.. cpp:function:: void interface_manager::operator =(const interface_manager &) = delete

   The copy assignment operator is deleted.

.. cpp:function:: virtual interface_manager::~interface_manager()

   Destructs an interface manager object.

.. cpp:function:: int interface_manager::debug_level() const

   Returns the current debug level of the interface manager object.
   The debug level controls the verbosity of debug logs.
   The default debug level is 0.

.. cpp:function:: void interface_manager::set_debug_level(int debug_level)

   Sets the current debug level of the interface manager object.


.. cpp:class:: rtnetlink_interface_manager: public interface_manager

   RTNETLINK-based interface manager objects for Linux.

   This implementation uses an RTNETLINK socket to communicate with the kernel.

.. cpp:function:: rtnetlink_interface_manager::rtnetlink_interface_manager()

.. cpp:function:: virtual rtnetlink_interface_manager::~rtnetlink_interface_manager()

   Destructs an RTNETLINK-based interface manager object.

.. cpp:function:: virtual void rtnetlink_interface_manager::refresh(bool maybe_asynchronous = false) override
