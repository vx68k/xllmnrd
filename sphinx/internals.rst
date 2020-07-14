Internals of Xenium LLMNR Responder
===================================

Interface managers
------------------

.. cpp:namespace:: xllmnrd

.. cpp:class:: interface_manager

.. cpp:function:: protected: \
                  interface_manager::interface_manager()

.. cpp:function:: virtual interface_manager::~interface_manager()

.. cpp:class:: rtnetlink_interface_manager: public interface_manager

   RTNETLINK-based interface managers for Linux.

   This implementation uses an RTNETLINK socket to communicate with the kernel.

.. cpp:function:: rtnetlink_interface_manager::rtnetlink_interface_manager()

.. cpp:function:: virtual rtnetlink_interface_manager::~rtnetlink_interface_manager()

   Destructs an RTNETLINK-based interface manager.

.. cpp:function:: virtual void rtnetlink_interface_manager::refresh(bool maybe_asynchronous = false) override
