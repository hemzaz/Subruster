use subruster::session_manager;

#[tokio::main]
async fn main() {
    let _ = session_manager::start_session_operations().await;
    
}