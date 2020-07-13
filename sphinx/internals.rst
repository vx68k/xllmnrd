Internals of Xenium LLMNR Responder
===================================

Interface managers
------------------

.. cpp:namespace:: xllmnrd

.. cpp:class:: interface_manager

.. cpp:class:: rtnetlink_interface_manager: public interface_manager

.. cpp:function:: rtnetlink_interface_manager::rtnetlink_interface_manager()

.. cpp:function:: rtnetlink_interface_manager::~rtnetlink_interface_manager()

.. cpp:function:: void rtnetlink_interface_manager::refresh(bool maybe_asynchronous = false) override
