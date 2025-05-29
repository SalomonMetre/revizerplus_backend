from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from app.core.config import settings

# Make sure your database_url uses async driver, e.g.:
# postgresql+asyncpg://user:password@host:port/dbname
async_database_url = settings.database_url.replace("postgresql://", "postgresql+asyncpg://")

engine = create_async_engine(async_database_url, echo=True)

# Async sessionmaker
AsyncSessionLocal = sessionmaker(
    bind=engine,
    class_=AsyncSession,
    autoflush=False,
    autocommit=False,
    expire_on_commit=False,
)

# Async dependency for FastAPI or similar frameworks
async def get_db():
    async with AsyncSessionLocal() as session:
        yield session
