-- Deleting a service counts the routes that use it, and its foreign key looks for them again.
create index routes_service_id on routes (service_id);
